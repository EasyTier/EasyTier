#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

use std::{
    env::current_exe,
    sync::{atomic::AtomicU32, Arc, Mutex},
    time::Duration,
};

use anyhow::Context;
use dashmap::DashMap;
use easytier::{
    common::config::{
        ConfigLoader, NetworkIdentity, PeerConfig, TomlConfigLoader, VpnPortalConfig,
    },
    utils::{cost_to_str, float_to_str, list_peer_route_pair},
};
use egui::{Align, Layout, Separator, Widget};
use egui_extras::{Column, Size, StripBuilder, TableBuilder};
use egui_modal::Modal;
use humansize::format_size;
use launcher::{EasyTierLauncher, MyNodeInfo};
use serde::{Deserialize, Serialize};
use text_list::TextListOption;

use easytier::rpc::cli::NatType;

pub mod launcher;
pub mod text_list;
pub mod toggle_switch;

#[derive(Deserialize, Serialize)]
struct TextsForI18n {
    // Main window
    network_config_label: String,

    config_change_notify: String,

    unnamed_network_name: String,
    new_network: String,
    del_network: String,

    current_status_label: String,
    running_text: String,
    stopped_text: String,

    virtual_ipv4_label: String,
    network_name_label: String,
    network_secret_label: String,

    networking_method_label: String,
    public_server_method: String,
    manual_method: String,
    standalone_method: String,
    public_server_url_label: String,
    peer_urls_label: String,

    proxy_cidr_label: String,

    optional_hint_text: String,

    enable_vpn_portal_label: String,
    vpn_portal_listen_port_label: String,
    vpn_portal_client_cidr_label: String,

    listerners_label: String,
    rpc_port_label: String,

    copy_config_button: String,

    advanced_settings: String,

    node_info_label: String,
    route_table_label: String,
    other_info_label: String,
    running_event_label: String,
    vpn_portal_info_btn: String,

    event_time_table_col: String,
    detail_table_col: String,
}

impl TextsForI18n {
    fn new_english() -> Self {
        Self {
            unnamed_network_name: "default".to_string(),

            new_network: "New Network".to_string(),
            del_network: "Remove Current".to_string(),

            current_status_label: "Current Status".to_string(),
            running_text: "Running. Press To Stop: ".to_string(),
            stopped_text: "Stopped, Press To Run: ".to_string(),
            config_change_notify: "*Config Changed. Need Rerun".to_string(),

            virtual_ipv4_label: "Virtual IPv4".to_string(),
            network_name_label: "Network Name".to_string(),
            network_secret_label: "Network Secret".to_string(),

            networking_method_label: "Networking Method".to_string(),
            public_server_method: "Public Server".to_string(),
            manual_method: "Manual".to_string(),
            standalone_method: "Standalone".to_string(),
            peer_urls_label: "Peer URLs".to_string(),

            optional_hint_text: "Optional".to_string(),

            enable_vpn_portal_label: "Enable VPN Portal".to_string(),
            vpn_portal_listen_port_label: "VPN Listen Port".to_string(),
            vpn_portal_client_cidr_label: "VPN Client CIDR".to_string(),

            listerners_label: "Listeners".to_string(),
            rpc_port_label: "RPC Port".to_string(),

            copy_config_button: "Copy Config".to_string(),

            advanced_settings: "Advanced Settings".to_string(),

            node_info_label: "Node Info".to_string(),
            route_table_label: "Route Table".to_string(),
            other_info_label: "Other Info".to_string(),
            running_event_label: "Running Event".to_string(),

            vpn_portal_info_btn: "VPN Portal Info".to_string(),

            network_config_label: "Network Config".to_string(),
            public_server_url_label: "Public Server URL".to_string(),
            proxy_cidr_label: "Proxy CIDR".to_string(),
            event_time_table_col: "Event Time".to_string(),
            detail_table_col: "Detail".to_string(),
        }
    }

    fn new_chinese() -> Self {
        Self {
            unnamed_network_name: "default".to_string(),
            new_network: "新建网络".to_string(),
            del_network: "删除当前".to_string(),

            current_status_label: "当前状态".to_string(),
            running_text: "运行中。点击停止: ".to_string(),
            stopped_text: "已停止，点击运行: ".to_string(),
            config_change_notify: "*配置已更改，需要重新运行".to_string(),

            virtual_ipv4_label: "虚拟IPv4".to_string(),
            network_name_label: "网络名称".to_string(),
            network_secret_label: "网络密钥".to_string(),

            networking_method_label: "组网方式".to_string(),
            public_server_method: "公共服务器".to_string(),
            manual_method: "手动".to_string(),
            standalone_method: "独立模式".to_string(),
            peer_urls_label: "节点URL".to_string(),

            optional_hint_text: "可选".to_string(),

            enable_vpn_portal_label: "启用VPN门户".to_string(),
            vpn_portal_listen_port_label: "VPN监听端口".to_string(),
            vpn_portal_client_cidr_label: "VPN客户端CIDR".to_string(),

            listerners_label: "监听器".to_string(),
            rpc_port_label: "RPC端口".to_string(),

            copy_config_button: "复制配置".to_string(),

            advanced_settings: "高级设置".to_string(),

            node_info_label: "节点信息".to_string(),
            route_table_label: "路由表".to_string(),
            other_info_label: "其他信息".to_string(),
            running_event_label: "运行事件".to_string(),

            vpn_portal_info_btn: "VPN门户信息".to_string(),

            network_config_label: "网络配置".to_string(),
            public_server_url_label: "公共服务器URL".to_string(),
            proxy_cidr_label: "子网代理".to_string(),
            event_time_table_col: "事件时间".to_string(),
            detail_table_col: "详情".to_string(),
        }
    }
}

static TEXTS_MAP: once_cell::sync::Lazy<DashMap<u32, TextsForI18n>> =
    once_cell::sync::Lazy::new(DashMap::new);

// 0: English, 1: Chinese
static LANGUAGE: AtomicU32 = AtomicU32::new(0);

static MESSAGE_BOX: once_cell::sync::Lazy<Arc<Mutex<Option<Modal>>>> =
    once_cell::sync::Lazy::new(Default::default);

#[macro_export]
macro_rules! TEXT {
    ($name:ident) => {
        TEXTS_MAP
            .get(&LANGUAGE.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap()
            .$name
            .clone()
    };
}

#[derive(derivative::Derivative, Deserialize, Serialize, PartialEq)]
enum NetworkingMethod {
    PublicServer,
    Manual,
    Standalone,
}

#[derive(derivative::Derivative, Deserialize, Serialize)]
struct NetworkInstancePane {
    running: bool,
    virtual_ipv4: String,
    network_name: String,
    network_secret: String,
    networking_method: NetworkingMethod,

    public_server_url: String,
    peer_urls: Vec<String>,

    proxy_cidrs: Vec<String>,

    enable_vpn_portal: bool,
    vpn_portal_listne_port: String,
    vpn_portal_client_cidr: String,

    advanced_settings: bool,

    listener_urls: Vec<String>,
    rpc_port: String,

    modal_title: String,
    modal_content: String,

    #[serde(skip)]
    launcher: Option<EasyTierLauncher>,
}

impl NetworkInstancePane {
    fn default() -> Self {
        Self {
            running: false,
            virtual_ipv4: "".to_string(),
            network_name: TEXT!(unnamed_network_name),
            network_secret: "".to_string(),
            networking_method: NetworkingMethod::PublicServer,

            public_server_url: "tcp://easytier.public.kkrainbow.top:11010".to_string(),
            peer_urls: vec![],

            proxy_cidrs: vec![],

            enable_vpn_portal: false,
            vpn_portal_listne_port: "11222".to_string(),
            vpn_portal_client_cidr: "10.14.14.0/24".to_string(),

            advanced_settings: false,

            listener_urls: vec![
                "tcp://0.0.0.0:11010".to_string(),
                "udp://0.0.0.0:11010".to_string(),
                "wg://0.0.0.0:11011".to_string(),
            ],

            rpc_port: "15888".to_string(),

            modal_title: "".to_string(),
            modal_content: "".to_string(),

            launcher: None,
        }
    }
}

impl NetworkInstancePane {
    fn gen_config(&self) -> Result<TomlConfigLoader, anyhow::Error> {
        let cfg = TomlConfigLoader::default();
        cfg.set_inst_name(self.network_name.clone());
        cfg.set_network_identity(NetworkIdentity {
            network_name: self.network_name.clone(),
            network_secret: self.network_secret.clone(),
        });

        if self.virtual_ipv4.len() > 0 {
            cfg.set_ipv4(
                self.virtual_ipv4.parse().with_context(|| {
                    format!("failed to parse ipv4 address: {}", self.virtual_ipv4)
                })?,
            )
        }

        match self.networking_method {
            NetworkingMethod::PublicServer => {
                cfg.set_peers(vec![PeerConfig {
                    uri: self.public_server_url.parse().with_context(|| {
                        format!(
                            "failed to parse public server uri: {}",
                            self.public_server_url
                        )
                    })?,
                }]);
            }
            NetworkingMethod::Manual => {
                let mut peers = vec![];
                for peer_url in self.peer_urls.iter() {
                    if peer_url.is_empty() {
                        continue;
                    }
                    peers.push(PeerConfig {
                        uri: peer_url
                            .parse()
                            .with_context(|| format!("failed to parse peer uri: {}", peer_url))?,
                    });
                }

                cfg.set_peers(peers);
            }
            NetworkingMethod::Standalone => {}
        }

        let mut listener_urls = vec![];
        for listener_url in self.listener_urls.iter() {
            if listener_url.is_empty() {
                continue;
            }
            listener_urls.push(
                listener_url
                    .parse()
                    .with_context(|| format!("failed to parse listener uri: {}", listener_url))?,
            );
        }
        cfg.set_listeners(listener_urls);

        for n in self.proxy_cidrs.iter() {
            cfg.add_proxy_cidr(
                n.parse()
                    .with_context(|| format!("failed to parse proxy network: {}", n))?,
            );
        }

        cfg.set_rpc_portal(
            format!("127.0.0.1:{}", self.rpc_port)
                .parse()
                .with_context(|| format!("failed to parse rpc portal port: {}", self.rpc_port))?,
        );

        if self.enable_vpn_portal {
            cfg.set_vpn_portal_config(VpnPortalConfig {
                client_cidr: self.vpn_portal_client_cidr.parse().with_context(|| {
                    format!(
                        "failed to parse vpn portal client cidr: {}",
                        self.vpn_portal_client_cidr
                    )
                })?,
                wireguard_listen: format!("0.0.0.0:{}", self.vpn_portal_listne_port)
                    .parse()
                    .with_context(|| {
                        format!(
                            "failed to parse vpn portal wireguard listen port. {}",
                            self.vpn_portal_listne_port
                        )
                    })?,
            });
        }

        Ok(cfg)
    }

    fn is_easytier_running(&self) -> bool {
        self.launcher.is_some() && self.launcher.as_ref().unwrap().running()
    }

    fn need_restart(&self) -> bool {
        let Ok(cfg) = self.gen_config() else {
            return false;
        };

        if !self.is_easytier_running() {
            return false;
        }

        self.launcher.as_ref().unwrap().running_cfg() != cfg.dump()
    }

    fn update_advanced_settings(&mut self, ui: &mut egui::Ui) {
        ui.label(TEXT!(listerners_label));
        text_list::text_list_ui(
            ui,
            "listeners",
            &mut self.listener_urls,
            Some(TextListOption {
                hint: "e.g: tcp://0.0.0.0:11010".to_string(),
            }),
        );
        ui.end_row();

        ui.label(TEXT!(rpc_port_label));
        ui.text_edit_singleline(&mut self.rpc_port);
        ui.end_row();
    }

    fn start_easytier(&mut self) {
        let mut l = EasyTierLauncher::new();
        l.start(|| self.gen_config());
        self.launcher = Some(l);
    }

    fn update_basic_settings(&mut self, ui: &mut egui::Ui) {
        ui.label(TEXT!(current_status_label));
        ui.horizontal(|ui| {
            if self.launcher.is_none() || !self.launcher.as_ref().unwrap().running() {
                self.running = false;
                ui.label(TEXT!(stopped_text));
            } else {
                self.running = true;
                ui.label(TEXT!(running_text));
            }

            if toggle_switch::toggle_ui(ui, &mut self.running).clicked() {
                if self.running {
                    self.start_easytier();
                } else {
                    self.launcher = None;
                }
            }

            if let Some(inst) = &self.launcher {
                ui.label(inst.error_msg().unwrap_or_default());
            }
        });
        ui.end_row();

        ui.label(TEXT!(virtual_ipv4_label));
        ui.horizontal(|ui| {
            egui::TextEdit::singleline(&mut self.virtual_ipv4)
                .hint_text("e.g: 10.144.144.3")
                .ui(ui);
            ui.label("/24");
        });
        ui.end_row();

        ui.label(TEXT!(network_name_label));
        egui::TextEdit::singleline(&mut self.network_name)
            .hint_text(TEXT!(optional_hint_text))
            .ui(ui);
        ui.end_row();

        ui.label(TEXT!(network_secret_label));
        egui::TextEdit::singleline(&mut self.network_secret)
            .hint_text(TEXT!(optional_hint_text))
            .ui(ui);
        ui.end_row();

        ui.label(TEXT!(networking_method_label));
        ui.horizontal(|ui| {
            ui.selectable_value(
                &mut self.networking_method,
                NetworkingMethod::PublicServer,
                TEXT!(public_server_method),
            );
            ui.selectable_value(
                &mut self.networking_method,
                NetworkingMethod::Manual,
                TEXT!(manual_method),
            );
            ui.selectable_value(
                &mut self.networking_method,
                NetworkingMethod::Standalone,
                TEXT!(standalone_method),
            );
        });
        ui.end_row();

        match self.networking_method {
            NetworkingMethod::PublicServer => {
                ui.label(TEXT!(public_server_url_label));
                ui.text_edit_singleline(&mut self.public_server_url);
                ui.end_row();
            }
            NetworkingMethod::Standalone => {}
            NetworkingMethod::Manual => {
                ui.label(TEXT!(peer_urls_label));
                text_list::text_list_ui(
                    ui,
                    "peers",
                    &mut self.peer_urls,
                    Some(TextListOption {
                        hint: "e.g: tcp://192.168.99.12:11010".to_string(),
                    }),
                );
                ui.end_row();
            }
        }

        ui.label(TEXT!(proxy_cidr_label));
        text_list::text_list_ui(
            ui,
            "proxy_cidr",
            &mut self.proxy_cidrs,
            Some(TextListOption {
                hint: "e.g: 10.147.223.0/24".to_string(),
            }),
        );
        ui.end_row();

        ui.label(TEXT!(enable_vpn_portal_label));
        toggle_switch::toggle_ui(ui, &mut self.enable_vpn_portal);
        ui.end_row();

        if self.enable_vpn_portal {
            ui.label(TEXT!(vpn_portal_listen_port_label));
            ui.text_edit_singleline(&mut self.vpn_portal_listne_port);
            ui.end_row();

            ui.label(TEXT!(vpn_portal_client_cidr_label));
            ui.text_edit_singleline(&mut self.vpn_portal_client_cidr);
            ui.end_row();
        }

        ui.label(TEXT!(advanced_settings));
        toggle_switch::toggle_ui(ui, &mut self.advanced_settings);
        ui.end_row();

        if self.advanced_settings {
            self.update_advanced_settings(ui);
        }
    }

    fn update_config_zone(&mut self, ui: &mut egui::Ui) {
        StripBuilder::new(ui)
            .size(Size::exact(25.0))
            .size(Size::remainder())
            .size(Size::exact(15.0))
            .size(Size::exact(100.0))
            .size(Size::exact(20.0))
            .vertical(|mut strip| {
                strip.cell(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(TEXT!(network_config_label));
                        if self.need_restart() {
                            ui.label(TEXT!(config_change_notify));
                        }
                    });
                });

                strip.cell(|ui| {
                    ui.with_layout(
                        Layout::top_down(Align::LEFT).with_cross_justify(true),
                        |ui| {
                            egui::ScrollArea::vertical().show(ui, |ui| {
                                egui::Grid::new("grid")
                                    .spacing([10.0, 15.0])
                                    .show(ui, |ui| {
                                        self.update_basic_settings(ui);
                                    });
                            });
                        },
                    );
                });

                strip.cell(|ui| {
                    Separator::default().spacing(10.0).ui(ui);
                });

                if let Ok(cfg) = self.gen_config() {
                    // ui.separator();
                    strip.cell(|ui| {
                        ui.with_layout(
                            Layout::top_down(Align::LEFT).with_cross_justify(true),
                            |ui| {
                                egui::ScrollArea::vertical().show(ui, |ui| {
                                    ui.text_edit_multiline(&mut cfg.dump());
                                });
                            },
                        );
                    });
                    strip.cell(|ui| {
                        ui.with_layout(
                            Layout::top_down(Align::Center).with_cross_justify(true),
                            |ui| {
                                if ui.button(TEXT!(copy_config_button)).clicked() {
                                    ui.output_mut(|o| o.copied_text = cfg.dump());
                                };
                            },
                        );
                    });
                } else {
                    strip.cell(|_ui| {});
                    strip.cell(|_ui| {});
                }
            });
        // ui.vertical_centered_justified(|ui| {
        //     ui.group(|ui| {});
        // });
    }

    fn update_event_table(&mut self, ui: &mut egui::Ui) {
        let table = TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::auto())
            .column(Column::remainder())
            .stick_to_bottom(true)
            .min_scrolled_height(0.0);

        let table = table.header(20.0, |mut header| {
            header.col(|ui| {
                ui.strong(TEXT!(event_time_table_col));
            });
            header.col(|ui| {
                ui.strong(TEXT!(detail_table_col));
            });
        });

        let mut events = vec![];
        if let Some(l) = self.launcher.as_ref() {
            if l.running() {
                events.extend(l.get_events());
            }
        };

        table.body(|mut body| {
            for (time, event) in events.iter() {
                body.row(20.0, |mut row| {
                    row.col(|ui| {
                        ui.monospace(time.format("%Y-%m-%d %H:%M:%S").to_string());
                    });
                    row.col(|ui| {
                        ui.monospace(format!("{:?}", event));
                    });
                });
            }
            if events.len() < 10 {
                for _ in 0..(10 - events.len()) {
                    body.row(20.0, |mut row| {
                        row.col(|ui| {
                            ui.monospace("".to_string());
                        });
                        row.col(|ui| {
                            ui.monospace("".to_string());
                        });
                    });
                }
            }
        });
    }

    fn update_node_info(&mut self, ui: &mut egui::Ui, node_info: MyNodeInfo) {
        let add_card = |ui: &mut egui::Ui, content: String| {
            if ui.button(&content).clicked() {
                ui.output_mut(|o| o.copied_text = content);
            };
        };

        ui.horizontal_wrapped(|ui| {
            add_card(
                ui,
                format!("{}: {}", "Virtual IPV4: ", node_info.virtual_ipv4),
            );

            add_card(
                ui,
                format!(
                    "{}: {:#?}",
                    "UDP NAT Type:",
                    NatType::try_from(node_info.stun_info.udp_nat_type).unwrap()
                ),
            );

            for (idx, l) in node_info.listeners.iter().enumerate() {
                add_card(ui, format!("Listener {}: {}", idx, l));
            }

            for (idx, ipv4) in node_info.ips.interface_ipv4s.iter().enumerate() {
                add_card(ui, format!("Local IPV4 {}: {}", idx, ipv4));
            }

            if node_info.ips.public_ipv4.len() > 0 {
                add_card(ui, format!("Public IPV4: {}", node_info.ips.public_ipv4));
            }
        });
    }

    fn update_route_table(&mut self, ui: &mut egui::Ui) {
        let table = TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::auto())
            .column(Column::auto())
            .column(Column::auto())
            .column(Column::auto())
            .column(Column::auto())
            .column(Column::auto())
            .column(Column::remainder())
            .stick_to_bottom(true)
            .min_scrolled_height(0.0);

        let table = table.header(20.0, |mut header| {
            header.col(|ui| {
                ui.strong("Virtual IP");
            });
            header.col(|ui| {
                ui.strong("HostName");
            });
            header.col(|ui| {
                ui.strong("Cost");
            });
            header.col(|ui| {
                ui.strong("Latency");
            });
            header.col(|ui| {
                ui.strong("TX");
            });
            header.col(|ui| {
                ui.strong("RX");
            });
            header.col(|ui| {
                ui.strong("LossRate");
            });
        });

        let mut peers = vec![];
        let mut routes = vec![];
        if let Some(l) = self.launcher.as_ref() {
            if l.running() {
                routes.extend(l.get_routes());
                peers.extend(l.get_peers());
            }
        };

        let pairs = list_peer_route_pair(peers, routes);

        table.body(|mut body| {
            for pair in pairs.iter() {
                body.row(20.0, |mut row| {
                    row.col(|ui| {
                        ui.monospace(&pair.route.ipv4_addr);
                    });
                    row.col(|ui| {
                        ui.monospace(pair.route.hostname.to_string());
                    });
                    row.col(|ui| {
                        ui.monospace(cost_to_str(pair.route.cost));
                    });
                    row.col(|ui| {
                        ui.monospace(float_to_str(pair.get_latency_ms().unwrap_or_default(), 2));
                    });
                    row.col(|ui| {
                        ui.monospace(format_size(
                            pair.get_tx_bytes().unwrap_or_default(),
                            humansize::DECIMAL,
                        ));
                    });
                    row.col(|ui| {
                        ui.monospace(format_size(
                            pair.get_rx_bytes().unwrap_or_default(),
                            humansize::DECIMAL,
                        ));
                    });
                    row.col(|ui| {
                        ui.monospace(float_to_str(pair.get_loss_rate().unwrap_or_default(), 2));
                    });
                });
            }
        });
    }

    fn update(&mut self, ui: &mut egui::Ui) -> egui_tiles::UiResponse {
        // Give each pane a unique color:
        // let color = egui::epaint::Hsva::new(0.103 as f32, 0.5, 0.5, 1.0);
        // ui.painter().rect_filled(ui.max_rect(), 0.0, color);
        ui.add(egui::Separator::default().spacing(5.0));

        const CONFIG_PANE_WIDTH: f32 = 440.0;

        let mut modal_ref = MESSAGE_BOX.lock().unwrap();
        let modal = modal_ref.as_mut().unwrap();
        modal.show(|ui| {
            // these helper functions help set the ui based on the modal's
            // set style, but they are not required and you can put whatever
            // ui you want inside [`.show()`]
            modal.title(ui, self.modal_title.clone());
            modal.frame(ui, |ui| {
                modal.body(ui, self.modal_content.clone());
            });
            modal.buttons(ui, |ui| {
                // After clicking, the modal is automatically closed
                if modal.button(ui, "Copy And Close").clicked() {
                    ui.output_mut(|o| o.copied_text = self.modal_content.clone());
                    modal.close();
                };
            });
        });

        let node_info = if let Some(l) = self.launcher.as_ref() {
            l.get_node_info()
        } else {
            Default::default()
        };

        StripBuilder::new(ui)
            .size(Size::exact(CONFIG_PANE_WIDTH))
            .size(Size::remainder())
            .horizontal(|mut strip| {
                strip.cell(|ui| {
                    self.update_config_zone(ui);
                });

                strip.strip(|builder| {
                    builder
                        .size(Size::exact(100.0))
                        .size(Size::relative(0.4))
                        .size(Size::exact(20.0))
                        .size(Size::remainder())
                        .vertical(|mut strip| {
                            strip.cell(|ui| {
                                ui.label(TEXT!(node_info_label));
                                ui.group(|ui| {
                                    egui::ScrollArea::both().show(ui, |ui| {
                                        self.update_node_info(ui, node_info.clone());
                                    });
                                });
                            });

                            strip.cell(|ui| {
                                ui.label(TEXT!(route_table_label));
                                ui.with_layout(
                                    Layout::top_down(Align::LEFT).with_cross_justify(true),
                                    |ui| {
                                        ui.group(|ui| {
                                            egui::ScrollArea::both().show(ui, |ui| {
                                                self.update_route_table(ui);
                                            });
                                        });
                                    },
                                );
                            });

                            strip.cell(|ui| {
                                ui.horizontal_wrapped(|ui| {
                                    ui.label(TEXT!(other_info_label));
                                    if ui.button(TEXT!(vpn_portal_info_btn)).clicked() {
                                        self.modal_title = TEXT!(vpn_portal_info_btn);
                                        self.modal_content =
                                            node_info.vpn_portal_cfg.unwrap_or_default();
                                        modal.open();
                                    }
                                });
                            });

                            strip.cell(|ui| {
                                ui.label(TEXT!(running_event_label));
                                ui.with_layout(
                                    Layout::top_down(Align::LEFT).with_cross_justify(true),
                                    |ui| {
                                        ui.group(|ui| {
                                            egui::ScrollArea::both().show(ui, |ui| {
                                                self.update_event_table(ui);
                                            });
                                        });
                                    },
                                );
                            });
                        });
                });
            });

        egui_tiles::UiResponse::None
    }
}

struct MainWindowTabsBehavior {
    simplification_options: egui_tiles::SimplificationOptions,
    add_child_to: Option<egui_tiles::TileId>,
    remove_child: Option<egui_tiles::TileId>,
}

impl Default for MainWindowTabsBehavior {
    fn default() -> Self {
        let simplification_options = egui_tiles::SimplificationOptions {
            all_panes_must_have_tabs: true,
            ..Default::default()
        };
        Self {
            simplification_options,
            add_child_to: None,
            remove_child: None,
        }
    }
}

// ref: https://github.com/rerun-io/egui_tiles/blob/main/examples/advanced.rs
impl egui_tiles::Behavior<NetworkInstancePane> for MainWindowTabsBehavior {
    fn tab_title_for_pane(&mut self, pane: &NetworkInstancePane) -> egui::WidgetText {
        format!("{}", pane.network_name).into()
    }

    fn pane_ui(
        &mut self,
        ui: &mut egui::Ui,
        _tile_id: egui_tiles::TileId,
        pane: &mut NetworkInstancePane,
    ) -> egui_tiles::UiResponse {
        pane.update(ui)
    }

    fn top_bar_right_ui(
        &mut self,
        _tiles: &egui_tiles::Tiles<NetworkInstancePane>,
        ui: &mut egui::Ui,
        tile_id: egui_tiles::TileId,
        _tabs: &egui_tiles::Tabs,
        _scroll_offset: &mut f32,
    ) {
        ui.add_space(7.0);
        let cur_lang = LANGUAGE.load(std::sync::atomic::Ordering::Relaxed);
        if ui
            .button(format!(
                "{}{}",
                "🌐",
                if cur_lang == 0 { "中" } else { "En" }
            ))
            .clicked()
        {
            LANGUAGE.store(1 - cur_lang, std::sync::atomic::Ordering::Relaxed);
        }

        ui.separator();

        if ui
            .button(format!("{}{}", "➕", TEXT!(new_network)))
            .clicked()
        {
            self.add_child_to = Some(tile_id);
        }

        if _tabs.children.len() > 1
            && ui
                .button(format!("{}{}", "➖", TEXT!(del_network)))
                .clicked()
        {
            if let Some(tid) = _tabs.active {
                self.remove_child = Some(tid);
            }
        }
    }

    fn simplification_options(&self) -> egui_tiles::SimplificationOptions {
        self.simplification_options
    }

    /// The height of the bar holding tab titles.
    fn tab_bar_height(&self, _style: &egui::Style) -> f32 {
        40.0
    }

    /// Width of the gap between tiles in a horizontal or vertical layout,
    /// and between rows/columns in a grid layout.
    fn gap_width(&self, _style: &egui::Style) -> f32 {
        1.0
    }

    /// No child should shrink below this width nor height.
    fn min_size(&self) -> f32 {
        32.0
    }

    /// Show we preview panes that are being dragged,
    /// i.e. show their ui in the region where they will end up?
    fn preview_dragged_panes(&self) -> bool {
        false
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
struct MyApp {
    tree: egui_tiles::Tree<NetworkInstancePane>,

    #[serde(skip)]
    behavior: MainWindowTabsBehavior,
}

impl MyApp {
    fn default() -> Self {
        let mut tiles = egui_tiles::Tiles::default();
        let mut tabs = vec![];
        tabs.push(tiles.insert_pane(NetworkInstancePane::default()));
        let root = tiles.insert_tab_tile(tabs);
        let tree = egui_tiles::Tree::new("my_tree", root, tiles);

        Self {
            tree,
            behavior: Default::default(),
        }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let Some(tile_id) = self.behavior.add_child_to.take() {
            let tiles = &mut self.tree.tiles;
            let new_pane = NetworkInstancePane::default();
            let new_tab = tiles.insert_pane(new_pane);
            if let Some(egui_tiles::Tile::Container(egui_tiles::Container::Tabs(tabs))) =
                self.tree.tiles.get_mut(tile_id)
            {
                tabs.add_child(new_tab);
                tabs.set_active(new_tab);
            }
        }

        if let Some(tile_id) = self.behavior.remove_child.take() {
            let tiles = &mut self.tree.tiles;
            tiles.remove(tile_id);
        }

        ctx.request_repaint_after(Duration::from_secs(1)); // animation
        egui::CentralPanel::default().show(ctx, |ui| {
            self.tree.ui(&mut self.behavior, ui);
        });
    }

    fn save(&mut self, _storage: &mut dyn eframe::Storage) {
        eframe::set_value(_storage, eframe::APP_KEY, &self);
    }
}

fn init_text_map() {
    TEXTS_MAP.insert(0, TextsForI18n::new_english());
    TEXTS_MAP.insert(1, TextsForI18n::new_chinese());
}

fn check_sudo() -> bool {
    let is_elevated = elevated_command::Command::is_elevated();
    if !is_elevated {
        let Ok(my_exe) = current_exe() else {
            return true;
        };
        let elevated_cmd = elevated_command::Command::new(std::process::Command::new(my_exe));
        let _ = elevated_cmd.output();
    }
    is_elevated
}

fn load_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "my_font".to_owned(),
        egui::FontData::from_static(include_bytes!("../assets/msyh.ttc")),
    );
    fonts
        .families
        .get_mut(&egui::FontFamily::Proportional)
        .unwrap()
        .insert(0, "my_font".to_owned());
    fonts
        .families
        .get_mut(&egui::FontFamily::Monospace)
        .unwrap()
        .push("my_font".to_owned());
    ctx.set_fonts(fonts);
}

fn main() -> Result<(), eframe::Error> {
    if !check_sudo() {
        return Ok(());
    }
    env_logger::init(); // Log to stderr (if you run with `RUST_LOG=debug`).
    init_text_map();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([800.0, 600.0]),
        ..Default::default()
    };

    eframe::run_native(
        "EasyTier",
        options,
        Box::new(|ctx| {
            load_fonts(&ctx.egui_ctx);
            let mut message_box = MESSAGE_BOX.lock().unwrap();
            *message_box = Some(Modal::new(&ctx.egui_ctx, "MessageBox"));

            let mut app = MyApp::default();
            if let Some(storage) = ctx.storage {
                if let Some(state) = eframe::get_value(storage, eframe::APP_KEY) {
                    app = state;
                }
            }
            Box::new(app)
        }),
    )
}
