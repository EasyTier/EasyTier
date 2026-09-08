package host

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/EasyTier/EasyTier/easytier-go/internal/contextutil"
	apiconfig "github.com/EasyTier/EasyTier/easytier-go/proto/api/config"
	apiinstance "github.com/EasyTier/EasyTier/easytier-go/proto/api/instance"
	"github.com/EasyTier/EasyTier/easytier-go/proto/api/manage"
	"github.com/EasyTier/EasyTier/easytier-go/proto/common"
	errorpb "github.com/EasyTier/EasyTier/easytier-go/proto/error"
	"google.golang.org/protobuf/proto"
)

const (
	runNetworkInstanceMethod       = "api.manage.WebClientService.RunNetworkInstance"
	retainNetworkInstanceMethod    = "api.manage.WebClientService.RetainNetworkInstance"
	collectNetworkInfoMethod       = "api.manage.WebClientService.CollectNetworkInfo"
	listNetworkInstanceMethod      = "api.manage.WebClientService.ListNetworkInstance"
	deleteNetworkInstanceMethod    = "api.manage.WebClientService.DeleteNetworkInstance"
	getNetworkInstanceConfigMethod = "api.manage.WebClientService.GetNetworkInstanceConfig"
	listNetworkInstanceMetaMethod  = "api.manage.WebClientService.ListNetworkInstanceMeta"
	patchConfigMethod              = "api.config.ConfigRpc.PatchConfig"
	getConfigMethod                = "api.config.ConfigRpc.GetConfig"
)

type instanceOwner uint8

const (
	instanceOwnerApplication instanceOwner = iota
	instanceOwnerWeb
)

type managedInstance struct {
	id         *common.UUID
	instance   *Instance
	owner      instanceOwner
	config     *manage.NetworkConfig
	configTOML string
	source     manage.ConfigSource
	name       string
}

type instanceManager struct {
	mu        sync.RWMutex
	mutations sync.Mutex
	host      *Host
	instances map[string]*managedInstance
}

func newInstanceManager() *instanceManager {
	return &instanceManager{instances: make(map[string]*managedInstance)}
}

func (manager *instanceManager) register(entry *managedInstance) error {
	id := uuidString(entry.id)
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if _, exists := manager.instances[id]; exists {
		return fmt.Errorf("EasyTier instance %s already exists", id)
	}
	manager.instances[id] = entry
	return nil
}

func (manager *instanceManager) remove(instance *Instance) {
	manager.mu.Lock()
	if entry := manager.instances[instance.id]; entry != nil &&
		entry.instance == instance {
		delete(manager.instances, instance.id)
	}
	manager.mu.Unlock()
}

func (manager *instanceManager) clear() {
	manager.mu.Lock()
	manager.instances = make(map[string]*managedInstance)
	manager.mu.Unlock()
}

func (manager *instanceManager) snapshot() []*managedInstance {
	manager.mu.RLock()
	entries := make([]*managedInstance, 0, len(manager.instances))
	for _, entry := range manager.instances {
		snapshot := *entry
		entries = append(entries, &snapshot)
	}
	manager.mu.RUnlock()
	sort.Slice(entries, func(i, j int) bool {
		return uuidString(entries[i].id) < uuidString(entries[j].id)
	})
	return entries
}

func (manager *instanceManager) handle(
	ctx context.Context,
	encoded []byte,
) []byte {
	started := time.Now()
	var envelope common.HostManagementRequest
	if err := proto.Unmarshal(encoded, &envelope); err != nil {
		return encodeManagementResponse(nil, err, started)
	}
	if envelope.Rpc == nil {
		return encodeManagementResponse(
			nil,
			fmt.Errorf("host management RPC is required"),
			started,
		)
	}
	response, err := manager.dispatch(
		ctx,
		envelope.Rpc.FullMethodName,
		envelope.Rpc.Request,
		envelope.GetPreparedConfig(),
		envelope.GetPreparedInstanceId(),
	)
	return encodeManagementResponse(response, err, started)
}

func (manager *instanceManager) dispatch(
	ctx context.Context,
	method string,
	encoded []byte,
	preparedConfig string,
	preparedInstanceID *common.UUID,
) (proto.Message, error) {
	switch method {
	case runNetworkInstanceMethod:
		request := new(manage.RunNetworkInstanceRequest)
		if err := proto.Unmarshal(encoded, request); err != nil {
			return nil, err
		}
		return manager.runNetworkInstance(
			ctx,
			request,
			preparedConfig,
			preparedInstanceID,
		)
	case retainNetworkInstanceMethod:
		request := new(manage.RetainNetworkInstanceRequest)
		if err := proto.Unmarshal(encoded, request); err != nil {
			return nil, err
		}
		return manager.retainNetworkInstances(ctx, request)
	case collectNetworkInfoMethod:
		request := new(manage.CollectNetworkInfoRequest)
		if err := proto.Unmarshal(encoded, request); err != nil {
			return nil, err
		}
		return manager.collectNetworkInfo(ctx, request)
	case listNetworkInstanceMethod:
		request := new(manage.ListNetworkInstanceRequest)
		if err := proto.Unmarshal(encoded, request); err != nil {
			return nil, err
		}
		return manager.listNetworkInstances(), nil
	case deleteNetworkInstanceMethod:
		request := new(manage.DeleteNetworkInstanceRequest)
		if err := proto.Unmarshal(encoded, request); err != nil {
			return nil, err
		}
		return manager.deleteNetworkInstances(ctx, request)
	case getNetworkInstanceConfigMethod:
		request := new(manage.GetNetworkInstanceConfigRequest)
		if err := proto.Unmarshal(encoded, request); err != nil {
			return nil, err
		}
		return manager.getNetworkInstanceConfig(request)
	case listNetworkInstanceMetaMethod:
		request := new(manage.ListNetworkInstanceMetaRequest)
		if err := proto.Unmarshal(encoded, request); err != nil {
			return nil, err
		}
		return manager.listNetworkInstanceMeta(request), nil
	case patchConfigMethod:
		request := new(apiconfig.PatchConfigRequest)
		if err := proto.Unmarshal(encoded, request); err != nil {
			return nil, err
		}
		return manager.patchConfig(ctx, request)
	case getConfigMethod:
		request := new(apiconfig.GetConfigRequest)
		if err := proto.Unmarshal(encoded, request); err != nil {
			return nil, err
		}
		return manager.getConfig(request)
	default:
		return nil, fmt.Errorf("unsupported host management method %q", method)
	}
}

func (manager *instanceManager) runNetworkInstance(
	ctx context.Context,
	request *manage.RunNetworkInstanceRequest,
	preparedConfig string,
	preparedInstanceID *common.UUID,
) (*manage.RunNetworkInstanceResponse, error) {
	if request.Config == nil {
		return nil, fmt.Errorf("config is required")
	}
	if preparedConfig == "" {
		return nil, fmt.Errorf("prepared EasyTier config is required")
	}
	if preparedInstanceID == nil {
		return nil, fmt.Errorf("prepared EasyTier instance ID is required")
	}
	request.InstId = cloneUUID(preparedInstanceID)
	id := uuidString(preparedInstanceID)
	request.Config.InstanceId = &id
	manager.mutations.Lock()
	defer manager.mutations.Unlock()

	manager.mu.RLock()
	previous := manager.instances[id]
	manager.mu.RUnlock()
	if previous != nil {
		if previous.owner != instanceOwnerWeb {
			return nil, fmt.Errorf("configuration for instance %s is read-only", id)
		}
		if !request.Overwrite && previous.instance.engine.TerminalError() == nil {
			return &manage.RunNetworkInstanceResponse{
				InstId: cloneUUID(request.InstId),
			}, nil
		}
		if err := closeManagedInstance(ctx, previous.instance); err != nil {
			return nil, fmt.Errorf("replace EasyTier instance %s: %w", id, err)
		}
	}
	source := request.Source
	if source == manage.ConfigSource_ConfigSourceUnspecified && previous != nil {
		source = previous.source
	}

	entry, err := manager.createWebInstance(
		ctx,
		request.InstId,
		request.Config,
		source,
		preparedConfig,
	)
	if err != nil && previous != nil {
		restoreContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, restoreErr := manager.createWebInstance(
			restoreContext,
			previous.id,
			previous.config,
			previous.source,
			previous.configTOML,
		)
		err = errors.Join(err, restoreErr)
	}
	if err != nil {
		return nil, err
	}
	return &manage.RunNetworkInstanceResponse{InstId: cloneUUID(entry.id)}, nil
}

func (manager *instanceManager) createWebInstance(
	ctx context.Context,
	id *common.UUID,
	config *manage.NetworkConfig,
	source manage.ConfigSource,
	configTOML string,
) (*managedInstance, error) {
	runtime, err := manager.host.engine.CreateInstance(ctx, configTOML)
	if err != nil {
		return nil, err
	}
	instance := &Instance{
		engine:  runtime,
		id:      uuidString(id),
		manager: manager,
	}
	if err := runtime.Start(ctx); err != nil {
		_ = runtime.Close(contextutil.WithoutCancel(ctx))
		return nil, err
	}
	if source == manage.ConfigSource_ConfigSourceUnspecified {
		source = manage.ConfigSource_ConfigSourceUser
	}
	entry := &managedInstance{
		id:         cloneUUID(id),
		instance:   instance,
		owner:      instanceOwnerWeb,
		config:     proto.Clone(config).(*manage.NetworkConfig),
		configTOML: configTOML,
		source:     source,
		name:       config.GetNetworkName(),
	}
	if err := manager.register(entry); err != nil {
		_ = runtime.Close(contextutil.WithoutCancel(ctx))
		return nil, err
	}
	return entry, nil
}

func (manager *instanceManager) patchConfig(
	ctx context.Context,
	request *apiconfig.PatchConfigRequest,
) (*apiconfig.PatchConfigResponse, error) {
	id, err := selectedInstanceID(request.Instance)
	if err != nil {
		return nil, err
	}
	key := uuidString(id)
	manager.mutations.Lock()
	defer manager.mutations.Unlock()

	manager.mu.RLock()
	entry := manager.instances[key]
	manager.mu.RUnlock()
	if entry == nil {
		return nil, fmt.Errorf("EasyTier instance %s not found", key)
	}
	if entry.owner != instanceOwnerWeb {
		return nil, fmt.Errorf("configuration for instance %s is read-only", key)
	}
	if request.Patch == nil {
		return new(apiconfig.PatchConfigResponse), nil
	}

	response := new(apiconfig.PatchConfigResponse)
	patchErr := entry.instance.callRPCRequest(
		ctx,
		patchConfigMethod,
		&apiconfig.PatchConfigRequest{
			Patch:    hostedConfigPatch(request.Patch),
			Instance: request.Instance,
		},
		response,
	)
	snapshotContext, cancel := context.WithTimeout(
		contextutil.WithoutCancel(ctx),
		10*time.Second,
	)
	defer cancel()
	effective := new(apiconfig.GetConfigResponse)
	if err := entry.instance.callRPCRequest(
		snapshotContext,
		getConfigMethod,
		&apiconfig.GetConfigRequest{Instance: request.Instance},
		effective,
	); err != nil {
		return nil, errors.Join(
			patchErr,
			fmt.Errorf("read effective EasyTier configuration: %w", err),
		)
	}
	if effective.Config == nil || effective.TomlConfig == "" {
		return nil, errors.Join(
			patchErr,
			fmt.Errorf("EasyTier instance %s returned an incomplete config snapshot", key),
		)
	}

	manager.mu.Lock()
	if manager.instances[key] != entry {
		manager.mu.Unlock()
		return nil, errors.Join(
			patchErr,
			fmt.Errorf("EasyTier instance %s is no longer running", key),
		)
	}
	entry.config = mergeHostedConfigPatch(entry.config, effective.Config, request.Patch)
	entry.configTOML = effective.TomlConfig
	manager.mu.Unlock()
	if patchErr != nil {
		return nil, patchErr
	}
	return response, nil
}

func (manager *instanceManager) getConfig(
	request *apiconfig.GetConfigRequest,
) (*apiconfig.GetConfigResponse, error) {
	id, err := selectedInstanceID(request.Instance)
	if err != nil {
		return nil, err
	}
	response, err := manager.getNetworkInstanceConfig(
		&manage.GetNetworkInstanceConfigRequest{InstId: id},
	)
	if err != nil {
		return nil, err
	}
	return &apiconfig.GetConfigResponse{Config: response.Config}, nil
}

func selectedInstanceID(
	identifier *apiinstance.InstanceIdentifier,
) (*common.UUID, error) {
	id := identifier.GetId()
	if id == nil {
		return nil, fmt.Errorf("instance ID is required")
	}
	return id, nil
}

func hostedConfigPatch(
	patch *apiconfig.InstanceConfigPatch,
) *apiconfig.InstanceConfigPatch {
	return &apiconfig.InstanceConfigPatch{
		PortForwards:     patch.PortForwards,
		Acl:              patch.Acl,
		ProxyNetworks:    patch.ProxyNetworks,
		DisableRelayData: patch.DisableRelayData,
	}
}

func mergeHostedConfigPatch(
	desired *manage.NetworkConfig,
	effective *manage.NetworkConfig,
	patch *apiconfig.InstanceConfigPatch,
) *manage.NetworkConfig {
	merged := proto.Clone(desired).(*manage.NetworkConfig)
	runtime := proto.Clone(effective).(*manage.NetworkConfig)
	if len(patch.PortForwards) != 0 {
		merged.PortForwards = runtime.PortForwards
	}
	if patch.Acl != nil {
		merged.Acl = runtime.Acl
	}
	if len(patch.ProxyNetworks) != 0 {
		merged.ProxyCidrs = runtime.ProxyCidrs
	}
	if patch.DisableRelayData != nil {
		merged.DisableRelayData = runtime.DisableRelayData
	}
	return merged
}

func (manager *instanceManager) retainNetworkInstances(
	ctx context.Context,
	request *manage.RetainNetworkInstanceRequest,
) (*manage.RetainNetworkInstanceResponse, error) {
	retained := uuidSet(request.InstIds)
	manager.mutations.Lock()
	defer manager.mutations.Unlock()
	if err := manager.closeWebInstances(ctx, func(id string) bool {
		_, keep := retained[id]
		return !keep
	}); err != nil {
		return nil, err
	}
	return &manage.RetainNetworkInstanceResponse{
		RemainInstIds: manager.instanceIDs(),
	}, nil
}

func (manager *instanceManager) deleteNetworkInstances(
	ctx context.Context,
	request *manage.DeleteNetworkInstanceRequest,
) (*manage.DeleteNetworkInstanceResponse, error) {
	deleted := uuidSet(request.InstIds)
	manager.mutations.Lock()
	defer manager.mutations.Unlock()
	if err := manager.closeWebInstances(ctx, func(id string) bool {
		_, remove := deleted[id]
		return remove
	}); err != nil {
		return nil, err
	}
	return &manage.DeleteNetworkInstanceResponse{
		RemainInstIds: manager.instanceIDs(),
	}, nil
}

func (manager *instanceManager) closeWebInstances(
	ctx context.Context,
	shouldClose func(string) bool,
) error {
	for _, entry := range manager.snapshot() {
		if entry.owner != instanceOwnerWeb ||
			!shouldClose(uuidString(entry.id)) {
			continue
		}
		if err := closeManagedInstance(ctx, entry.instance); err != nil {
			return err
		}
	}
	return nil
}

func closeManagedInstance(ctx context.Context, instance *Instance) error {
	alreadyFailed := instance.engine.TerminalError() != nil
	err := instance.Close(ctx)
	if alreadyFailed && ctx.Err() == nil {
		return nil
	}
	return err
}

func (manager *instanceManager) listNetworkInstances() *manage.ListNetworkInstanceResponse {
	return &manage.ListNetworkInstanceResponse{InstIds: manager.instanceIDs()}
}

func (manager *instanceManager) instanceIDs() []*common.UUID {
	entries := manager.snapshot()
	ids := make([]*common.UUID, len(entries))
	for index, entry := range entries {
		ids[index] = cloneUUID(entry.id)
	}
	return ids
}

func (manager *instanceManager) collectNetworkInfo(
	ctx context.Context,
	request *manage.CollectNetworkInfoRequest,
) (*manage.CollectNetworkInfoResponse, error) {
	included := uuidSet(request.InstIds)
	info := make(map[string]*manage.NetworkInstanceRunningInfo)
	for _, entry := range manager.snapshot() {
		id := uuidString(entry.id)
		if len(included) != 0 {
			if _, exists := included[id]; !exists {
				continue
			}
		}
		snapshot, err := entry.runningInfo(ctx)
		if err != nil {
			return nil, err
		}
		info[id] = snapshot
	}
	return &manage.CollectNetworkInfoResponse{
		Info: &manage.NetworkInstanceRunningInfoMap{Map: info},
	}, nil
}

func (entry *managedInstance) runningInfo(
	ctx context.Context,
) (*manage.NetworkInstanceRunningInfo, error) {
	state := entry.instance.State()
	running := state != StateCreated && state != StateStopped
	info := &manage.NetworkInstanceRunningInfo{
		Running: running,
		Events:  entry.instance.engine.ManagementEvents(),
	}
	if err := entry.instance.engine.TerminalError(); err != nil {
		message := err.Error()
		info.ErrorMsg = &message
	}
	if state != StateRunning {
		return info, nil
	}
	peers, err := entry.instance.listPeerResponse(ctx)
	if err != nil {
		return nil, err
	}
	routes, err := entry.instance.listRouteResponse(ctx)
	if err != nil {
		return nil, err
	}
	nodeResponse, err := entry.instance.showNodeInfo(ctx)
	if err != nil {
		return nil, err
	}
	foreign, err := entry.instance.foreignNetworkSummary(ctx)
	if err != nil {
		return nil, err
	}
	node := nodeResponse.NodeInfo
	listeners := make([]*common.Url, len(node.GetListeners()))
	for index, listener := range node.GetListeners() {
		listeners[index] = &common.Url{Url: listener}
	}
	var virtualIPv4 *common.Ipv4Inet
	for _, route := range routes.Routes {
		if route.PeerId == node.GetPeerId() {
			virtualIPv4 = route.Ipv4Addr
			break
		}
	}
	info.DevName = entry.config.GetDevName()
	info.MyNodeInfo = &manage.MyNodeInfo{
		VirtualIpv4: virtualIPv4,
		Hostname:    node.GetHostname(),
		Version:     node.GetVersion(),
		Ips:         node.GetIpList(),
		StunInfo:    node.GetStunInfo(),
		Listeners:   listeners,
		PeerId:      node.GetPeerId(),
	}
	info.Routes = routes.Routes
	info.Peers = peers.PeerInfos
	info.PeerRoutePairs = peerRoutePairs(peers.PeerInfos, routes.Routes)
	info.ForeignNetworkSummary = foreign.Summary
	return info, nil
}

func (manager *instanceManager) getNetworkInstanceConfig(
	request *manage.GetNetworkInstanceConfigRequest,
) (*manage.GetNetworkInstanceConfigResponse, error) {
	if request.InstId == nil {
		return nil, fmt.Errorf("instance ID is required")
	}
	id := uuidString(request.InstId)
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	entry := manager.instances[id]
	if entry == nil {
		return nil, fmt.Errorf("EasyTier instance %s not found", id)
	}
	if entry.owner != instanceOwnerWeb {
		return nil, fmt.Errorf("configuration for instance %s is read-only", id)
	}
	config := proto.Clone(entry.config).(*manage.NetworkConfig)
	return &manage.GetNetworkInstanceConfigResponse{
		Config: config,
		Source: entry.source,
	}, nil
}

func (manager *instanceManager) listNetworkInstanceMeta(
	request *manage.ListNetworkInstanceMetaRequest,
) *manage.ListNetworkInstanceMetaResponse {
	included := uuidSet(request.InstIds)
	response := &manage.ListNetworkInstanceMetaResponse{}
	for _, entry := range manager.snapshot() {
		if _, exists := included[uuidString(entry.id)]; !exists {
			continue
		}
		permission := uint32(0)
		if entry.owner == instanceOwnerApplication {
			permission = 3
		}
		networkName := entry.name
		if entry.config != nil {
			networkName = entry.config.GetNetworkName()
		}
		response.Metas = append(response.Metas, &manage.NetworkMeta{
			InstId:           cloneUUID(entry.id),
			NetworkName:      networkName,
			ConfigPermission: permission,
			InstanceName:     entry.name,
			Source:           entry.source,
		})
	}
	return response
}

func encodeManagementResponse(
	response proto.Message,
	responseErr error,
	started time.Time,
) []byte {
	runtimeUs := uint64(time.Since(started).Microseconds())
	if runtimeUs == 0 {
		runtimeUs = 1
	}
	envelope := &common.RpcResponse{
		RuntimeUs: runtimeUs,
	}
	if responseErr == nil {
		envelope.Response, responseErr = proto.Marshal(response)
	}
	if responseErr != nil {
		envelope.Error = &errorpb.Error{
			ErrorKind: &errorpb.Error_ExecuteError{
				ExecuteError: &errorpb.ExecuteError{
					ErrorMessage: responseErr.Error(),
				},
			},
		}
	}
	encoded, err := proto.Marshal(envelope)
	if err != nil {
		panic("marshal EasyTier RPC response: " + err.Error())
	}
	return encoded
}

func peerRoutePairs(
	peers []*apiinstance.PeerInfo,
	routes []*apiinstance.Route,
) []*apiinstance.PeerRoutePair {
	byID := make(map[uint32]*apiinstance.PeerInfo, len(peers))
	for _, peer := range peers {
		byID[peer.PeerId] = peer
	}
	pairs := make([]*apiinstance.PeerRoutePair, 0, len(routes))
	for _, route := range routes {
		if peer := byID[route.PeerId]; peer != nil {
			pairs = append(pairs, &apiinstance.PeerRoutePair{
				Route: route,
				Peer:  peer,
			})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		left, right := pairs[i].Route, pairs[j].Route
		leftPublic := left.GetFeatureFlag().GetIsPublicServer()
		rightPublic := right.GetFeatureFlag().GetIsPublicServer()
		if leftPublic != rightPublic {
			return leftPublic
		}
		return left.GetIpv4Addr().GetAddress().GetAddr() <
			right.GetIpv4Addr().GetAddress().GetAddr()
	})
	return pairs
}

func parseInstanceUUID(text string) (*common.UUID, string, error) {
	normalized := strings.ReplaceAll(strings.TrimSpace(text), "-", "")
	if len(normalized) != 32 {
		return nil, "", fmt.Errorf("invalid EasyTier instance ID %q", text)
	}
	var value [16]byte
	decoded, err := hex.DecodeString(normalized)
	if err != nil || len(decoded) != 16 {
		return nil, "", fmt.Errorf("invalid EasyTier instance ID %q", text)
	}
	copy(value[:], decoded)
	id := &common.UUID{
		Part1: binary.BigEndian.Uint32(value[0:4]),
		Part2: binary.BigEndian.Uint32(value[4:8]),
		Part3: binary.BigEndian.Uint32(value[8:12]),
		Part4: binary.BigEndian.Uint32(value[12:16]),
	}
	return id, uuidString(id), nil
}

func newInstanceUUID() (*common.UUID, string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return nil, "", fmt.Errorf("generate EasyTier instance ID: %w", err)
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	id := &common.UUID{
		Part1: binary.BigEndian.Uint32(value[0:4]),
		Part2: binary.BigEndian.Uint32(value[4:8]),
		Part3: binary.BigEndian.Uint32(value[8:12]),
		Part4: binary.BigEndian.Uint32(value[12:16]),
	}
	return id, uuidString(id), nil
}

func uuidString(id *common.UUID) string {
	var value [16]byte
	binary.BigEndian.PutUint32(value[0:4], id.GetPart1())
	binary.BigEndian.PutUint32(value[4:8], id.GetPart2())
	binary.BigEndian.PutUint32(value[8:12], id.GetPart3())
	binary.BigEndian.PutUint32(value[12:16], id.GetPart4())
	return fmt.Sprintf(
		"%x-%x-%x-%x-%x",
		value[0:4],
		value[4:6],
		value[6:8],
		value[8:10],
		value[10:16],
	)
}

func cloneUUID(id *common.UUID) *common.UUID {
	if id == nil {
		return nil
	}
	return &common.UUID{
		Part1: id.Part1,
		Part2: id.Part2,
		Part3: id.Part3,
		Part4: id.Part4,
	}
}

func uuidSet(ids []*common.UUID) map[string]struct{} {
	set := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if id != nil {
			set[uuidString(id)] = struct{}{}
		}
	}
	return set
}

func bindInstanceIdentity(config, id, name string) string {
	var encoded strings.Builder
	writeTOMLStringField(&encoded, "instance_id", id)
	writeTOMLStringField(&encoded, "instance_name", name)
	encoded.WriteByte('\n')
	encoded.WriteString(config)
	return encoded.String()
}
