import { Elysia, t } from "elysia";
import { cors } from "@elysiajs/cors";
import { swagger } from "@elysiajs/swagger";
import { sql } from "bun";
import jwt from "@elysiajs/jwt";

const SEVEN_DAYS_IN_SEC = 604800;

const userSignUpSchema = t.Object({
  username: t.String({ minLength: 3 }),
  email: t.String({ format: "email" }),
  password: t.String(),
  full_name: t.String(),
  roles: t.Optional(t.Array(t.Integer())),
});

const userSignInSchema = t.Object({
  username: t.String({ minLength: 3 }),
  password: t.String(),
});

const writeRefreshToken = async (
  user_id: number,
  refresh: string,
  exp: Date
) => {
  try {
    await sql`delete from refresh_tokens where user_id = ${user_id}`;
    await sql`
      insert into refresh_tokens (token, user_id, expires_at)
      values (${refresh}, ${user_id}, ${exp})
    `;
    return null;
  } catch (e) {
    console.log(e);
  }
};

const app = new Elysia()
  .use(cors())
  .use(swagger())
  .use(
    jwt({
      name: "jwt",
      secret: Bun.env.JWT_SECRET!,
      schema: t.Object({
        id: t.Integer(),
        issue_date: t.Date(),
        exp_date: t.Date(),
        roles: t.Array(t.Integer()),
      }),
    })
  )
  .use(
    jwt({
      name: "jwt_refresh",
      secret: Bun.env.JWT_SECRET_REFRESH!,
      schema: t.Object({
        id: t.Integer(),
        date: t.Date(),
      }),
      exp: "7d",
    })
  )
  .derive(async ({ query, headers, jwt }) => {
    const auth = headers["authorization"];
    const token = auth && auth.startsWith("Bearer ") ? auth.slice(7) : null;
    if (!token) return { user: null };
    const user = await jwt.verify(token);
    if (user) {
      const now = new Date(Date.now());
      const exp_date = new Date(user.exp_date);
      if (!exp_date || exp_date < now) return { user: null };
      return { user };
    }
    return { user: null };
  })
  .post(
    "/signin",
    async ({ body, set, jwt, jwt_refresh, cookie: { auth } }) => {
      const { username, password } = body;
      const u = await sql`
        select 
          u.id, u.password_hash, array_agg(ur.role_id) as role_ids, u.full_name
        from users u
        inner join user_roles ur
          on u.id = ur.user_id
        where u.username = ${username}
        group by u.id, u.password_hash
      `;
      if (u.count < 1) {
        set.status = 400;
        return { error: "User does not exist" };
      }
      const user = u[0];
      const roles: number[] = Array.from<number>(user.role_ids);
      const isPassCorrect = await Bun.password.verify(
        password,
        user.password_hash,
        "bcrypt"
      );
      if (!isPassCorrect) {
        set.status = 400;
        return { error: "Pasword is incorrect" };
      }
      const now = new Date(Date.now());
      const access_expire_date = new Date(now.getTime() + 2700000);
      const refresh_expire_date = new Date(
        now.getTime() + SEVEN_DAYS_IN_SEC * 1000
      );

      const token = await jwt.sign({
        id: user.id,
        issue_date: now,
        exp_date: access_expire_date,
        roles: roles,
      });
      const refresh_token = await jwt_refresh.sign({ id: user.id, date: now });
      await writeRefreshToken(user.id, refresh_token, refresh_expire_date);
      auth.set({
        value: refresh_token,
        httpOnly: true,
        maxAge: SEVEN_DAYS_IN_SEC,
      });
      return {
        access_token: token,
        user: { id: user.id, roles: roles, full_name: user.full_name },
      };
    },
    {
      body: userSignInSchema,
    }
  )
  .get(
    "/refresh_token",
    async ({ jwt_refresh, jwt, cookie: { auth }, set }) => {
      if (!auth.value) {
        set.status = 401;
        return { error: "Missing refresh_token" };
      }
      const jwtPayload = await jwt_refresh.verify(auth.value);
      if (!jwtPayload) {
        set.status = 403;
        return { error: "Invalid refresh_token" };
      }
      const { id, exp } = jwtPayload;
      if (!id || !exp) {
        set.status = 403;
        return { error: "Invalid refresh_token" };
      }
      const now = new Date(Date.now());
      const expDate = new Date(exp * 1000);
      if (now > expDate) {
        set.status = 403;
        return { error: "Expired refresh_token, please sign in again" };
      }
      const db_token = await sql`
      select token, user_id, expires_at
      from refresh_tokens where token = ${auth.value}
    `;
      if (
        !db_token ||
        db_token[0].user_id != id ||
        db_token[0].expires_at < now
      ) {
        set.status = 403;
        return { error: "Invalid refresh_token" };
      }

      const roles = await sql`
        select array_agg(role_id) as role_ids from user_roles where user_id = ${id}
      `;
      const role_ids: number[] = Array.from<number>(roles[0].role_ids);

      const refresh_expire_date = new Date(
        now.getTime() + SEVEN_DAYS_IN_SEC * 1000
      );
      const access_expire_date = new Date(now.getTime() + 2700000);
      const refresh_token = await jwt_refresh.sign({ id: id, date: now });
      await writeRefreshToken(id, refresh_token, refresh_expire_date);
      auth.set({
        value: refresh_token,
        httpOnly: true,
        maxAge: SEVEN_DAYS_IN_SEC,
      });
      const token = await jwt.sign({
        id: id,
        issue_date: now,
        exp_date: access_expire_date,
        roles: role_ids,
      });
      return { access_token: token };
    }
  )
  .group("/sip", (app) =>
    app.get(
      "/calls",
      async ({ query, user, set }) => {
        if (!user) {
          set.status = 401;
          return { error: "You are unauthorized" };
        }

        let where_clauses: string[] = [];

        if (query.call_id) {
          where_clauses.push(`sid = '${query.call_id}'`);
        }
        if (query.create_date) {
          where_clauses.push(`create_date = '${query.create_date}'`);
        }
        if (query.caller) {
          if (query.caller.includes("*")) {
            where_clauses.push(
              `caller like '${query.caller.replace(/\*/g, "%")}'`
            );
          } else {
            where_clauses.push(`caller = '${query.caller}'`);
          }
        }
        if (query.callee) {
          if (query.callee.includes("*")) {
            where_clauses.push(
              `callee like '${query.callee.replace(/\*/g, "%")}'`
            );
          } else {
            where_clauses.push(`callee = '${query.callee}'`);
          }
        }
        if (query.sip_status) {
          if (query.sip_status.includes("*")) {
            where_clauses.push(
              `sip_status like '${query.sip_status.replace(/\*/g, "%")}'`
            );
          } else {
            where_clauses.push(`sip_status = '${query.sip_status}'`);
          }
        }

        let qq = `
          select sid, create_date, start_date, end_date, caller, callee, sip_status
          from hep_brief_call_records
          where start_date >= '${query.start_date}' and start_date <= '${query.end_date}'
        `;

        let count_qq = `
          select count(*) as total
          from hep_brief_call_records
          where start_date >= '${query.start_date}' and start_date <= '${query.end_date}'
        `;

        if (where_clauses.length > 0) {
          qq += "and " + where_clauses.join(" and ");
          count_qq += "and " + where_clauses.join(" and ");
        }

        const count_res = await sql.unsafe(count_qq);
        const count_total = count_res[0].total;

        const offset = (query.page - 1) * query.per_page;
        qq += `order by start_date desc limit ${query.per_page} offset ${offset}`;
        const calls = await sql.unsafe(qq);
        const total_pages = Math.ceil(count_total / query.per_page);

        return {
          calls: calls,
          page: query.page,
          page_size: query.per_page,
          total: count_total,
          total_pages: total_pages,
        };
      },
      {
        query: t.Object({
          call_id: t.Optional(t.String()),
          caller: t.Optional(t.String()),
          callee: t.Optional(t.String()),
          sip_status: t.Optional(t.String()),
          page: t.Integer({ minimum: 1, default: 1 }),
          per_page: t.Integer({ minimum: 5, default: 15, maximum: 500 }),
          start_date: t.String({ format: "date-time" }),
          end_date: t.String({ format: "date-time" }),
          create_date: t.Optional(t.String({ format: "date-time" })),
        }),
      }
    )
  )
  .group("/users", (app) =>
    app
      .get("/all", async ({ user, set }) => {
        if (!user) {
          set.status = 401;
          return { error: "You are unauthorized" };
        }
        const users = await sql`
          select 
            u.id, u.username, u.full_name,
            json_agg(distinct jsonb_build_object(
              'role_id', ur.role_id,
              'role_id', rol.id,
              'role_name', rol.name
            )) as roles_perms
          from users u
          left join user_roles ur on u.id = ur.user_id
          left join roles rol on ur.role_id = rol.id 
          group by u.id, u.username, u.full_name
        `;
        return { users };
      })
      .get("/me", async ({ user, set }) => {
        if (!user) {
          set.status = 401;
          return { error: "You are unauthorized" };
        }
        const you = await sql`
          select 
            u.id, u.username, u.full_name,
            json_agg(distinct jsonb_build_object(
              'role_id', ur.role_id,
              'role_id', rol.id,
              'role_name', rol.name
            )) as roles_perms
          from users u
          left join user_roles ur on u.id = ur.user_id
          left join roles rol on ur.role_id = rol.id 
          where u.id = ${user.id}
          group by u.id, u.username, u.full_name
        `;
        if (!you) {
          set.status = 401;
          return { error: "You should not be here!" };
        }
        return { you: you };
      })
      .get("/roles", async ({ user, set }) => {
        if (!user) {
          set.status = 401;
          return { error: "You are unauthorized" };
        }
        const roles = await sql`
          select id, name, description, created_at from roles
        `;
        return { roles: roles };
      })
      .post(
        "create",
        async ({ body, set, user }) => {
          if (!user) {
            set.status = 401;
            return { error: "You are unauthorized" };
          }
          const { username, email, password, full_name, roles } = body;
          const uu = await sql`
            select id from users
            where username = ${username} or email = ${email}
          `;
          if (uu.count > 0) {
            set.status = 400;
            return { error: "User already exists" };
          }
          const pass_hash = await Bun.password.hash(password, "bcrypt");
          const newUser = await sql`
            insert into users (username, email, password_hash, full_name)
            values (${username}, ${email}, ${pass_hash}, ${full_name}) returning id
          `;
          if (!newUser) {
            set.status = 500;
            return {
              error:
                "An error happened while creating the user but it was not yours, try again or contact an admin :)",
            };
          }

          if (roles) {
            for (let role of roles) {
              const p = await sql`
                insert into user_roles (user_id, role_id)
                values (${newUser[0].id}, ${role})
              `;
            }
          }

          return { message: `User ${username} has been created` };
        },
        {
          body: userSignUpSchema,
        }
      )
  )
  .listen(3000);

console.log(
  `🦊 Elysia is running at ${app.server?.hostname}:${app.server?.port}`
);
