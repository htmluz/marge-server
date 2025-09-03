import { Elysia, t } from "elysia";
import { cors } from "@elysiajs/cors";
import { swagger } from "@elysiajs/swagger";
import { sql } from "bun";
import jwt from "@elysiajs/jwt";
import { RtcpStreamGroup } from "./types";

const SEVEN_DAYS_IN_SEC = 604800;

const userSignUpSchema = t.Object({
  username: t.String({ minLength: 3 }),
  email: t.String({ format: "email" }),
  password: t.String({ minLength: 8 }),
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
      try {
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
          console.log(u);
          set.status = 404;
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
        const refresh_token = await jwt_refresh.sign({
          id: user.id,
          date: now,
        });
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
      } catch (e) {
        console.log(e);
      }
    },
    {
      body: userSignInSchema,
    }
  )
  .post(
    "/change-password",
    async ({ body, user, set }) => {
      if (!user) {
        set.status = 401;
        return { error: "You are unauthorized" };
      }
      const { id, old_password, new_password } = body;

      if (old_password === new_password) {
        set.status = 400;
        return {
          message: "Your new password should not match your old password",
        };
      }

      const zz = await sql`
        select 
          u.password_hash
        from users u
        where u.id = ${id};
      `;

      if (zz.count < 1) {
        set.status = 404;
        return { message: "User does not exist" };
      }

      const pass_hash = zz[0].password_hash;
      const isPassCorrect = await Bun.password.verify(
        old_password,
        pass_hash,
        "bcrypt"
      );

      if (!isPassCorrect) {
        set.status = 400;
        return { message: "Your password is incorrect" };
      }

      const new_pass_hash = await Bun.password.hash(new_password, "bcrypt");

      const new_pass_update = await sql`
        update users
        set password_hash = ${new_pass_hash}
        where id = ${id};
      `;

      console.log(new_pass_update);
      return { message: "Password changed successfully" };
    },
    {
      body: t.Object({
        id: t.Integer(),
        old_password: t.String(),
        new_password: t.String({ minLength: 8 }),
      }),
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
    app
      .get(
        "/calls",
        async ({ query, user, set }) => {
          if (!user) {
            set.status = 401;
            return { error: "You are unauthorized" };
          }

          let where_clauses: string[] = [];

          if (query.sid) {
            if (query.sid.includes("*")) {
              where_clauses.push(`sid like '${query.sid.replace(/\*/g, "%")}'`);
            } else {
              where_clauses.push(`sid = '${query.sid}'`);
            }
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

          let qq = `
            select sid, create_date, caller, callee
            from hep_brief_call_records
            where create_date >= '${query.start_date}' and create_date <= '${query.end_date}'
          `;

          let count_qq = `
            select count(*) as total
            from hep_brief_call_records
            where create_date >= '${query.start_date}' and create_date <= '${query.end_date}'
          `;

          if (where_clauses.length > 0) {
            qq += "and " + where_clauses.join(" and ");
            count_qq += "and " + where_clauses.join(" and ");
          }

          const count_res = await sql.unsafe(count_qq);
          const count_total = count_res[0].total;

          const offset = (query.page - 1) * query.per_page;
          qq += `order by create_date desc limit ${query.per_page} offset ${offset}`;
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
            sid: t.Optional(t.String()),
            caller: t.Optional(t.String()),
            callee: t.Optional(t.String()),
            page: t.Integer({ minimum: 1, default: 1 }),
            per_page: t.Integer({ minimum: 5, default: 15, maximum: 500 }),
            start_date: t.String({ format: "date-time" }),
            end_date: t.String({ format: "date-time" }),
          }),
        }
      )
      .get(
        "/call-detail",
        async ({ query, user, set }) => {
          if (!user) {
            set.status = 401;
            return { error: "You are unauthorized" };
          }
          const call_ids = query.sids;
          if (call_ids.length < 1) return { detail: [] };

          interface fodase {
            call_id: string;
          }
          const zz: fodase[] = call_ids.map((z) => {
            return { call_id: z };
          });
          const calls = await sql`
            with call_messages as (
              select sid, 
                to_jsonb(hep_proto_1_call) - 'sid' as message_data,
                protocol_header->>'srcIp' as src_ip,
                protocol_header->>'dstIp' as dst_ip,
                (protocol_header->>'timeSeconds')::bigint as time_seconds,
                (protocol_header->>'timeUseconds')::bigint as time_useconds
              from hep_proto_1_call 
              where sid in ${sql(zz, "call_id")}
            ),
            unique_ips AS (
              select distinct unnest(ARRAY[src_ip, dst_ip]) as ip
              from call_messages
            ),
            ip_mappings AS (
              select ui.ip, coalesce(inc.name, ui.ip) as name
              from unique_ips ui
              left join ip_names_correlation inc on ui.ip = inc.ip
            ),
            ip_map_json AS (
              select jsonb_object_agg(ip, name) as ip_to_name_map
              from ip_mappings
            )
            select 
              cm.sid,
              json_agg(
                cm.message_data || jsonb_build_object(
                  'srcipname', (select ip_to_name_map->>cm.src_ip from ip_map_json),
                  'dstipname', (select ip_to_name_map->>cm.dst_ip from ip_map_json)
                )
                order by cm.time_seconds, cm.time_useconds
              ) as messages,
              (select ip_to_name_map from ip_map_json) as ip_mappings
            from call_messages cm
            group by cm.sid;
          `;
          return { detail: calls };
        },
        {
          query: t.Object({
            sids: t.Array(t.String()),
            rtcp: t.Boolean(),
          }),
        }
      )
      .get(
        "registers-domains",
        async ({ query, user, set }) => {
          if (!user) {
            set.status = 401;
            return { error: "You are unauthorized" };
          }

          const { start_date, end_date } = query;
          const domains = await sql`
            select array_agg(distinct hpr.data_header ->> 'ruri_domain') as domains
            from hep_proto_1_registration hpr
            where hpr.data_header ->> 'method' = 'REGISTER' and hpr.create_date >= ${start_date} and hpr.create_date <= ${end_date};
          `;
          return { data: domains[0].domains };
        },
        {
          query: t.Object({
            start_date: t.String({ format: "date-time" }),
            end_date: t.String({ format: "date-time" }),
          }),
        }
      )
      .get(
        "registers-watch",
        async ({ query, user, set }) => {
          if (!user) {
            set.status = 401;
            return { error: "You are unauthorized" };
          }

          const { domain, users, start_date, end_date } = query;

          let packets = [];

          if (users) {
            interface fodase {
              users: string;
            }
            const zz: fodase[] = users.map((z) => {
              return { users: z };
            });

            packets = await sql`
              select t1.* from hep_proto_1_registration t1
              join (
                select distinct hpr.sid 
                from hep_proto_1_registration hpr 
                where hpr.data_header ->> 'ruri_domain' = ${domain} and hpr.create_date >= ${start_date} and hpr.create_date <= ${end_date} and hpr.data_header ->> 'from_user' in ${sql(
              zz,
              "users"
            )}
              ) as filtered_sids
              on t1.sid = filtered_sids.sid
              where t1.create_date >= ${start_date} and t1.create_date <= ${end_date};`;
          } else {
            packets = await sql`
                select t1.* from hep_proto_1_registration t1
                join (
                  select distinct hpr.sid 
                  from hep_proto_1_registration hpr 
                  where hpr.data_header ->> 'ruri_domain' = ${domain} and hpr.create_date >= ${start_date} and hpr.create_date <= ${end_date}) as filtered_sids
                on t1.sid = filtered_sids.sid
                where t1.create_date >= ${start_date} and t1.create_date <= ${end_date};`;
          }

          return { data: packets };
        },
        {
          query: t.Object({
            domain: t.String({ minLength: 1 }),
            users: t.Optional(t.Array(t.String())),
            start_date: t.String({ format: "date-time" }),
            end_date: t.String({ format: "date-time" }),
          }),
        }
      )
      .get(
        "rtcp-detail",
        async ({ query, user, set }) => {
          if (!user) {
            set.status = 401;
            return { error: "You are unauthorized" };
          }

          const streams: RtcpStreamGroup[] = await sql`
            select
              protocol_header->>'srcIp' AS src_ip,
              protocol_header->>'srcPort' as src_port,
              protocol_header->>'dstIp' AS dst_ip,
              protocol_header->>'dstPort' as dst_port,
              json_agg(
                jsonb_build_object(
                  'timestamp', to_timestamp(
                    (protocol_header->>'timeSeconds')::bigint +
                      (protocol_header->>'timeUseconds')::bigint / 1000000.0
                  ),
                  'raw', raw::jsonb
                )
                order by
                  (protocol_header->>'timeSeconds')::bigint,
                  (protocol_header->>'timeUseconds')::bigint
              ) as streams
            from
              hep_proto_5_default
            where
              sid = ${query.sids}
            group by
              protocol_header->>'srcIp',
              protocol_header->>'srcPort',
              protocol_header->>'dstIp',
              protocol_header->>'dstPort';
          `;

          for (const stream of streams) {
            for (const packet of stream.streams) {
              function calculateMOS(
                fractionLost: number,
                jitter: number,
                delay: number
              ) {
                const effectiveDelay = (delay || 0) + 2 * (jitter || 0);
                let R = 94.2 - effectiveDelay / 2 - fractionLost * 2.5;
                if (R < 0) R = 0;
                if (R > 100) R = 100;
                const MOS = 1 + 0.035 * R + 7e-6 * R * (R - 60) * (100 - R);
                return Math.max(1, Math.min(4.5, MOS));
              }
              if (packet.raw.type === 207) {
                packet.raw["mos"] = calculateMOS(
                  packet.raw.report_blocks[0].fraction_lost,
                  packet.raw.report_blocks[0].ia_jitter,
                  packet.raw.report_blocks_xr.round_trip_delay
                );
              } else {
                packet.raw["mos"] = 0.0;
              }
            }
          }
          return { streams };
        },
        {
          query: t.Object({
            sids: t.String(),
          }),
        }
      )
      .get(
        "/trunks",
        async ({ query, user, set }) => {
          if (!user) {
            set.status = 401;
            return { error: "You are unauthorized" };
          }
          const gateways = await sql`
            select id, ip, name, description from ip_names_correlation order by id asc;
          `;

          return { gateways };
        },
        {
          query: t.Object({
            name: t.Optional(t.Array(t.String())),
            ip: t.Optional(t.Array(t.String())),
          }),
        }
      )
      .post(
        "/trunks",
        async ({ body, user, set }) => {
          if (!user) {
            set.status = 401;
            return { error: "You are unauthorized" };
          }
          const { name, ip, description } = body;

          const newTrunk = await sql`
            insert into ip_names_correlation (ip, name, description)
            values (${ip}, ${name}, ${description}) returning id
          `;

          if (!newTrunk) {
            set.status = 500;
            return {
              error:
                "An error happened while creating the trunk but it was not yours, try again or contact an admin :)",
            };
          }

          return {
            message: `Trunk ${name} - ${ip} has been created with the id ${newTrunk[0].id}`,
          };
        },
        {
          body: t.Object({
            name: t.String({ maxLength: 255 }),
            ip: t.String({ format: "ipv4" }),
            description: t.Optional(t.String({ maxLength: 255 })),
          }),
        }
      )
      .delete(
        "/trunks",
        async ({ body, user, set }) => {
          // if (!user) {
          //   set.status = 401;
          //   return { error: "You are unauthorized" };
          // }
        },
        {
          body: t.Object({
            id: t.Integer(),
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
        "/create",
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
            return {
              error: "User with this email or username already exists.",
            };
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
  `Marge-Server is running at ${app.server?.hostname}:${app.server?.port} 🤕`
);
