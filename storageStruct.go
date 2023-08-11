package main

import (
	"crypto/rsa"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/deepch/vdk/av"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var Storage = NewStreamCore()

// Default stream  type
const (
	MSE = iota
	WEBRTC
	RTSP
)

// Default stream status type
const (
	OFFLINE = iota
	ONLINE
)

// Default stream errors
var (
	Success                         = "success"
	ErrorStreamNotFound             = errors.New("stream not found")
	ErrorStreamAlreadyExists        = errors.New("stream already exists")
	ErrorStreamChannelAlreadyExists = errors.New("stream channel already exists")
	ErrorStreamNotHLSSegments       = errors.New("stream hls not ts seq found")
	ErrorStreamNoVideo              = errors.New("stream no video")
	ErrorStreamNoClients            = errors.New("stream no clients")
	ErrorStreamRestart              = errors.New("stream restart")
	ErrorStreamStopCoreSignal       = errors.New("stream stop core signal")
	ErrorStreamStopRTSPSignal       = errors.New("stream stop rtsp signal")
	ErrorStreamChannelNotFound      = errors.New("stream channel not found")
	ErrorStreamChannelCodecNotFound = errors.New("stream channel codec not ready, possible stream offline")
	ErrorStreamsLen0                = errors.New("streams len zero")
	ErrorStreamUnauthorized         = errors.New("stream request unauthorized")
	ErrorIncorrectRoleID            = errors.New("RoleID Incorrect")
)

// StorageST main storage struct
type StorageST struct {
	mutex           sync.RWMutex
	Server          ServerST            `json:"server" groups:"api,config"`
	Streams         map[string]StreamST `json:"streams,omitempty" groups:"api,config"`
	ChannelDefaults ChannelST           `json:"channel_defaults,omitempty" groups:"api,config"`
}

/*"http_login": "dem",
  "http_password": "dem",*/
// ServerST server storage section
type ServerST struct {
	Debug              bool          `json:"debug" groups:"api,config"`
	LogLevel           logrus.Level  `json:"log_level" groups:"api,config"`
	HTTPDemo           bool          `json:"http_demo" groups:"api,config"`
	HTTPDebug          bool          `json:"http_debug" groups:"api,config"`
	tokenStringSuper   string        `groups:"api,config"`
	tokenString        string        `groups:"api,config"`
	tokenRefesh        string        `groups:"api,config"`
	expiresAt          int64         `groups:"api,config"`
	RTexpiresAt        int64         `groups:"api,config"`
	publicKey          rsa.PublicKey `groups:"api,config"`
	RoleIDNow          string        `json:"roleid_now" groups:"api,config"`
	RoleLevelNow       string        `json:"rolelevel_now" groups:"api,config"`
	GroupID            string        `json:"group_id,omitempty" bson:"group_id,omitempty" groups:"api,config"`
	Username           string        `json:"username,omitempty" groups:"api,config"`
	HTTPLogin          string        `json:"http_login" groups:"api,config"`
	HTTPPassword       string        `json:"http_password" groups:"api,config"`
	HTTPDir            string        `json:"http_dir" groups:"api,config"`
	HTTPPort           string        `json:"http_port" groups:"api,config"`
	RTSPPort           string        `json:"rtsp_port" groups:"api,config"`
	HTTPS              bool          `json:"https" groups:"api,config"`
	HTTPSPort          string        `json:"https_port" groups:"api,config"`
	HTTPSCert          string        `json:"https_cert" groups:"api,config"`
	HTTPSKey           string        `json:"https_key" groups:"api,config"`
	HTTPSAutoTLSEnable bool          `json:"https_auto_tls" groups:"api,config"`
	HTTPSAutoTLSName   string        `json:"https_auto_tls_name" groups:"api,config"`
	ICEServers         []string      `json:"ice_servers" groups:"api,config"`
	ICEUsername        string        `json:"ice_username" groups:"api,config"`
	ICECredential      string        `json:"ice_credential" groups:"api,config"`
	Token              Token         `json:"token,omitempty" groups:"api,config"`
	WebRTCPortMin      uint16        `json:"webrtc_port_min" groups:"api,config"`
	WebRTCPortMax      uint16        `json:"webrtc_port_max" groups:"api,config"`
}

// Token auth
type Token struct {
	Enable  bool   `json:"enable" groups:"api,config"`
	Backend string `json:"backend" groups:"api,config"`
}

// ServerST stream storage section
type StreamST struct {
	Username  string               `json:"username,omitempty" groups:"api,config"`
	UUID      string               `json:"uuid,omitempty" bson:"uuid,omitempty" groups:"api,config"`
	GroupID   string               `json:"group_id,omitempty" bson:"group_id,omitempty" groups:"api,config"`
	RoleLevel string               `json:"role_level,omitempty" bson:"role_level,omitempty" groups:"api,config"`
	Name      string               `json:"name,omitempty" bson:"name,omitempty" groups:"api,config"`
	Channels  map[string]ChannelST `json:"channels,omitempty" bson:"channels,omitempty" groups:"api,config"`
}

type ChannelST struct {
	Name               string `json:"name,omitempty" bson:"name,omitempty" groups:"api,config"`
	URL                string `json:"url,omitempty" bson:"url,omitempty" groups:"api,config"`
	OnDemand           bool   `json:"on_demand,omitempty" bson:"on_demand,omitempty" groups:"api,config"`
	Debug              bool   `json:"debug,omitempty" bson:"debug,omitempty" groups:"api,config"`
	Status             int    `json:"status,omitempty" bson:"status,omitempty" groups:"api"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty" bson:"insecure_skip_verify,omitempty"  groups:"api,config"`
	Audio              bool   `json:"audio,omitempty" bson:"audio,omitempty" groups:"api,config"`
	runLock            bool
	codecs             []av.CodecData
	sdp                []byte
	signals            chan int
	hlsSegmentBuffer   map[int]SegmentOld
	hlsSegmentNumber   int
	clients            map[string]ClientST
	ack                time.Time
	hlsMuxer           *MuxerHLS `json:"-"`
}
type SaveToken struct {
	Username string `json:"username,omitempty" groups:"api,config"`
	Token    string `json:"token,omitempty" groups:"api,config"`
}
type UserLogin struct {
	Username string `json:"username,omitempty" groups:"api,config"`
	Password string `json:"password,omitempty" groups:"api,config"`
}
type ChangePassword struct {
	Old_Password string `json:"old_password,omitempty" groups:"api,config"`
	New_Password string `json:"new_password,omitempty" groups:"api,config"`
}
type User struct {
	Username     string           `json:"username,omitempty" groups:"api,config"`
	Password     string           `json:"password,omitempty" groups:"api,config"`
	GroupID      string           `json:"group_id,omitempty" bson:"group_id,omitempty" groups:"api,config"`
	RoleLevel    string           `json:"role_level,omitempty" bson:"role_level,omitempty" groups:"api,config"`
	PrivateKey   primitive.Binary `json:"private_key,omitempty" bson:"private_key,omitempty" groups:"api,config"`
	RefreshToken string           `json:"refresh_token,omitempty" bson:"refresh_token,omitempty" groups:"api,config"`
}

type Group struct {
	NameGroup string `json:"name_group,omitempty" bson:"name_group,omitempty" groups:"api,config"`
	IDGroup   string `json:"id_group,omitempty" bson:"id_group,omitempty" groups:"api,config"`
}
type Role struct {
	IDRole    string `json:"id_role,omitempty" bson:"id_role,omitempty" groups:"api,config"`
	LevelRole string `json:"level_role,omitempty" bson:"level_role,omitempty" groups:"api,config"`
}
type FindUUID struct {
	UUID string `json:"uuid,omitempty" bson:"uuid,omitempty" groups:"api,config"`
}
type FindUsername struct {
	Username string `json:"username,omitempty" bson:"username,omitempty" groups:"api,config"`
}
type token_Expired struct {
	Username              string `json:"username,omitempty" bson:"username,omitempty" groups:"api,config"`
	TokenExpired          string `json:tokenexpired,omitempty" bson:"tokenexpired,omitempty" groups:"api,config"`
	token_refresh_expired string `json:token_refresh_expired,omitempty" bson:"token_refresh_expired,omitempty" groups:"api,config"`
}

// ClientST client storage section
type ClientST struct {
	mode              int
	signals           chan int
	outgoingAVPacket  chan *av.Packet
	outgoingRTPPacket chan *[]byte
	socket            net.Conn
}

// SegmentOld HLS cache section
type SegmentOld struct {
	dur  time.Duration
	data []*av.Packet
}
