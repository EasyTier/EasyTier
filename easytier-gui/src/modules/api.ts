import { type Api, type NetworkTypes } from "easytier-frontend-lib";
import * as backend from "~/composables/backend";
import { loadMode } from "~/composables/mode";
import { checkElevationForTun } from "~/composables/elevation";

export type ElevationHandler = () => Promise<boolean>;

export class GUIRemoteClient implements Api.RemoteClient {
    private elevationHandler?: ElevationHandler;

    constructor(elevationHandler?: ElevationHandler) {
        this.elevationHandler = elevationHandler;
    }

    private async checkAndPromptElevation(): Promise<boolean> {
        const currentMode = loadMode();
        const hasElevation = await checkElevationForTun(currentMode);
        if (!hasElevation && this.elevationHandler) {
            await this.elevationHandler();
            return false;
        }
        return hasElevation;
    }

    async validate_config(config: NetworkTypes.NetworkConfig): Promise<Api.ValidateConfigResponse> {
        return backend.validateConfig(config);
    }
    async run_network(config: NetworkTypes.NetworkConfig, save: boolean): Promise<undefined> {
        if (!config.no_tun) {
            const canProceed = await this.checkAndPromptElevation();
            if (!canProceed) {
                return;
            }
        }
        await backend.runNetworkInstance(config, save);
    }
    async get_network_info(inst_id: string): Promise<NetworkTypes.NetworkInstanceRunningInfo | undefined> {
        return backend.collectNetworkInfo(inst_id).then(infos => infos.info.map[inst_id]);
    }
    async list_network_instance_ids(): Promise<Api.ListNetworkInstanceIdResponse> {
        return backend.listNetworkInstanceIds();
    }
    async delete_network(inst_id: string): Promise<undefined> {
        await backend.deleteNetworkInstance(inst_id);
    }
    async update_network_instance_state(inst_id: string, disabled: boolean): Promise<undefined> {
        if (!disabled) {
            const config = await backend.getConfig(inst_id);
            if (!config.no_tun) {
                const canProceed = await this.checkAndPromptElevation();
                if (!canProceed) {
                    return;
                }
            }
        }
        await backend.updateNetworkConfigState(inst_id, disabled);
    }
    async save_config(config: NetworkTypes.NetworkConfig): Promise<undefined> {
        await backend.saveNetworkConfig(config);
    }
    async get_network_config(inst_id: string): Promise<NetworkTypes.NetworkConfig> {
        return backend.getConfig(inst_id);
    }
    async generate_config(config: NetworkTypes.NetworkConfig): Promise<Api.GenerateConfigResponse> {
        try {
            return { toml_config: await backend.parseNetworkConfig(config) };
        } catch (e) {
            return { error: e + "" };
        }
    }
    async parse_config(toml_config: string): Promise<Api.ParseConfigResponse> {
        try {
            return { config: await backend.generateNetworkConfig(toml_config) }
        } catch (e) {
            return { error: e + "" };
        }
    }
    async get_network_metas(instance_ids: string[]): Promise<Api.GetNetworkMetasResponse> {
        return await backend.getNetworkMetas(instance_ids);
    }

}
