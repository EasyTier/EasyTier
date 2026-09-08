package host

import (
	"context"
	"fmt"
	"time"

	apiinstance "github.com/EasyTier/EasyTier/easytier-go/proto/api/instance"
	"github.com/EasyTier/EasyTier/easytier-go/proto/common"
	"google.golang.org/protobuf/proto"
)

const (
	listPeerRPCMethod              = "api.instance.PeerManageRpc.ListPeer"
	listRouteRPCMethod             = "api.instance.PeerManageRpc.ListRoute"
	showNodeInfoRPCMethod          = "api.instance.PeerManageRpc.ShowNodeInfo"
	foreignNetworkSummaryRPCMethod = "api.instance.PeerManageRpc.GetForeignNetworkSummary"
)

// PeerInfo describes one peer visible to an EasyTier instance.
type PeerInfo = apiinstance.PeerInfo

// Route describes one route visible to an EasyTier instance.
type Route = apiinstance.Route

// NodeInfo describes this EasyTier instance.
type NodeInfo = apiinstance.NodeInfo

// ListPeer returns the peers visible to this EasyTier instance.
func (instance *Instance) ListPeer(
	ctx context.Context,
) ([]*PeerInfo, error) {
	response, err := instance.listPeerResponse(ctx)
	if err != nil {
		return nil, err
	}
	return response.PeerInfos, nil
}

// ListRoute returns the routing table visible to this EasyTier instance.
func (instance *Instance) ListRoute(
	ctx context.Context,
) ([]*Route, error) {
	response, err := instance.listRouteResponse(ctx)
	if err != nil {
		return nil, err
	}
	return response.Routes, nil
}

func (instance *Instance) listPeerResponse(
	ctx context.Context,
) (*apiinstance.ListPeerResponse, error) {
	response := new(apiinstance.ListPeerResponse)
	if err := instance.callRPC(ctx, listPeerRPCMethod, response); err != nil {
		return nil, err
	}
	return response, nil
}

func (instance *Instance) listRouteResponse(
	ctx context.Context,
) (*apiinstance.ListRouteResponse, error) {
	response := new(apiinstance.ListRouteResponse)
	if err := instance.callRPC(ctx, listRouteRPCMethod, response); err != nil {
		return nil, err
	}
	return response, nil
}

// ShowNodeInfo returns this instance's node information, including its
// virtual IPv4 address and advertised hostname.
func (instance *Instance) ShowNodeInfo(ctx context.Context) (*NodeInfo, error) {
	response, err := instance.showNodeInfo(ctx)
	if err != nil {
		return nil, err
	}
	if response.NodeInfo == nil {
		return nil, fmt.Errorf("EasyTier ShowNodeInfo returned no node info")
	}
	return response.NodeInfo, nil
}

func (instance *Instance) showNodeInfo(
	ctx context.Context,
) (*apiinstance.ShowNodeInfoResponse, error) {
	response := new(apiinstance.ShowNodeInfoResponse)
	if err := instance.callRPC(ctx, showNodeInfoRPCMethod, response); err != nil {
		return nil, err
	}
	return response, nil
}

func (instance *Instance) foreignNetworkSummary(
	ctx context.Context,
) (*apiinstance.GetForeignNetworkSummaryResponse, error) {
	response := new(apiinstance.GetForeignNetworkSummaryResponse)
	if err := instance.callRPC(
		ctx,
		foreignNetworkSummaryRPCMethod,
		response,
	); err != nil {
		return nil, err
	}
	return response, nil
}

func (instance *Instance) callRPC(
	ctx context.Context,
	fullMethodName string,
	response proto.Message,
) error {
	return instance.callRPCRequest(ctx, fullMethodName, nil, response)
}

func (instance *Instance) callRPCRequest(
	ctx context.Context,
	fullMethodName string,
	request proto.Message,
	response proto.Message,
) error {
	if instance == nil || instance.engine == nil {
		return fmt.Errorf("call RPC through nil EasyTier instance")
	}
	if ctx == nil {
		return fmt.Errorf("call EasyTier RPC with nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var timeoutMillis *uint64
	if deadline, exists := ctx.Deadline(); exists {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return context.DeadlineExceeded
		}
		millis := uint64(remaining / time.Millisecond)
		if remaining%time.Millisecond != 0 {
			millis++
		}
		timeoutMillis = &millis
	}
	var payload []byte
	var err error
	if request != nil {
		payload, err = proto.Marshal(request)
		if err != nil {
			return fmt.Errorf("encode EasyTier RPC %s request: %w", fullMethodName, err)
		}
	}
	encodedRequest, err := proto.Marshal(&common.DirectRpcRequest{
		FullMethodName: fullMethodName,
		Request:        payload,
		TimeoutMs:      timeoutMillis,
	})
	if err != nil {
		return fmt.Errorf("encode EasyTier RPC envelope: %w", err)
	}
	encodedResponse, err := instance.engine.RPC(ctx, encodedRequest)
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	if err != nil {
		return err
	}
	var envelope common.RpcResponse
	if err := proto.Unmarshal(encodedResponse, &envelope); err != nil {
		return fmt.Errorf("decode EasyTier RPC %s response: %w", fullMethodName, err)
	}
	if envelope.Error != nil {
		return fmt.Errorf(
			"EasyTier RPC %s failed: %s",
			fullMethodName,
			envelope.Error,
		)
	}
	if err := proto.Unmarshal(envelope.Response, response); err != nil {
		return fmt.Errorf(
			"decode EasyTier RPC %s payload: %w",
			fullMethodName,
			err,
		)
	}
	return nil
}
