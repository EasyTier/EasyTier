import { v4 as uuidv4 } from 'uuid';

export enum NetworkingMethod {
  PublicServer = "PublicServer",
  Manual = "Manual",
  Standalone = "Standalone",
}

export interface NetworkConfig {
  instance_id: string,

  virtual_ipv4: string
  network_name: string
  network_secret: string

  networking_method: NetworkingMethod,

  public_server_url: string,
  peer_urls: Array<string>,

  proxy_cidrs: Array<string>,

  enable_vpn_portal: boolean,
  vpn_portal_listne_port: number,
  vpn_portal_client_network_addr: string,
  vpn_portal_client_network_len: number,

  advanced_settings: boolean,

  listener_urls: Array<string>,
  rpc_port: number,
}

export const DEFAULT_NETWORK_CONFIG = (): NetworkConfig => {
  return {
    instance_id: uuidv4(),

    virtual_ipv4: "",
    network_name: "default",
    network_secret: "",

    networking_method: NetworkingMethod.PublicServer,

    public_server_url: "tcp://easytier.public.kkrainbow.top:11010",
    peer_urls: [],

    proxy_cidrs: [],

    enable_vpn_portal: false,
    vpn_portal_listne_port: 22022,
    vpn_portal_client_network_addr: "",
    vpn_portal_client_network_len: 24,

    advanced_settings: false,

    listener_urls: [
      "tcp://0.0.0.0:11010",
      "udp://0.0.0.0:11010",
      "wg://0.0.0.0:11011",
    ],
    rpc_port: 15888,
  }
}

export interface NetworkInstance {
  instance_id: string,

  running: boolean,
  error_msg: string,

  detail: any,
}