export interface RtcpDBRes {
  streams: RtcpStreamGroup[];
}

export interface RtcpStreamGroup {
  src_ip: string;
  src_port: string;
  dst_ip: string;
  dst_port: string;
  streams: RtcpStream[];
}

export interface RtcpStream {
  raw: RtcpRaw;
  timestamp: string;
}

export interface RtcpRaw {
  ssrc: number;
  type: number;
  sdes_ssrc: number;
  report_count: number;
  report_blocks: RtcpReportBlock[];
  report_blocks_xr: RtcpReportBlockXR;
  sender_information: RtcpSenderInformation;
  mos: number;
}

export interface RtcpReportBlock {
  lsr: number;
  dlsr: number;
  ia_jitter: number;
  source_ssrc: number;
  packet_lost: number;
  fraction_lost: number;
  highest_seq_no: number;
}

export interface RtcpReportBlockXR {
  id: number;
  type: number;
  gap_density: number;
  gap_duration: number;
  burst_density: number;
  fraction_lost: number;
  burst_duration: number;
  end_system_delay: number;
  fraction_discard: number;
  round_trip_delay: number;
}

export interface RtcpSenderInformation {
  octets: number;
  packets: number;
  rtp_timestamp: number;
  ntp_timestamp_sec: number;
  ntp_timestamp_usec: number;
}
