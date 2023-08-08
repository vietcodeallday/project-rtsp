package main

import (
	"path/filepath"

	"github.com/sirupsen/logrus"
)

var (
	//Default www static file dir
	DefaultHTTPDir = "web"
)

/*func (obj *StorageST) CreateToken(c *gin.Context) (string, string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Issuer:    "viet",
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
	})
	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return "", "", err
	}
	c.JSON(200, "token: "+tokenString)
	fmt.Println("login sau la", obj.Server.HTTPLogin)
	return obj.Server.HTTPLogin, obj.Server.HTTPPassword, nil

}
*/
/*func (obj *StorageST) CheckToken() {
	if Storage.ServerHTTPLogin() != "" && Storage.ServerHTTPPassword() != "" {
		gin.BasicAuth(gin.Accounts{Storage.ServerHTTPLogin(): Storage.ServerHTTPPassword()})
	}
}*/

// ServerHTTPDir
func (obj *StorageST) ServerHTTPDir() string {
	obj.mutex.RLock()
	defer obj.mutex.RUnlock()
	if filepath.Clean(obj.Server.HTTPDir) == "." {
		return DefaultHTTPDir
	}
	return filepath.Clean(obj.Server.HTTPDir)
}

// ServerHTTPDebug read debug options
func (obj *StorageST) ServerHTTPDebug() bool {
	obj.mutex.RLock()
	defer obj.mutex.RUnlock()
	return obj.Server.HTTPDebug
}

// ServerLogLevel read debug options
func (obj *StorageST) ServerLogLevel() logrus.Level {
	obj.mutex.RLock()
	defer obj.mutex.RUnlock()
	return obj.Server.LogLevel
}

// ServerHTTPDemo read demo options
func (obj *StorageST) ServerHTTPDemo() bool {
	obj.mutex.RLock()
	defer obj.mutex.RUnlock()
	return obj.Server.HTTPDemo
}

// ServerHTTPLogin read Login options
func (obj *StorageST) ServerHTTPLogin() string {
	obj.mutex.RLock()
	defer obj.mutex.RUnlock()
	return obj.Server.HTTPLogin
}
func (obj *StorageST) CheckExpire() int64 {
	obj.mutex.RLock()
	defer obj.mutex.RUnlock()
	return obj.Server.expiresAt
}
func (obj *StorageST) CheckRTExpire() int64 {
	obj.mutex.RLock()
	defer obj.mutex.RUnlock()
	return obj.Server.RTexpiresAt
}
func (obj *StorageST) CheckTokenSuper() string {
	obj.mutex.RLock()
	defer obj.mutex.RUnlock()
	return obj.Server.tokenStringSuper
}
func (obj *StorageST) CheckToken() string {
	obj.mutex.RLock()
	defer obj.mutex.RUnlock()
	return obj.Server.tokenString
}
func (obj *StorageST) CheckTokenRefresh() string {
	obj.mutex.RLock()
	defer obj.mutex.RUnlock()
	return obj.Server.tokenRefesh
}

// ServerHTTPPassword read Password options
func (obj *StorageST) ServerHTTPPassword() string {
	obj.mutex.RLock()
	defer obj.mutex.RUnlock()
	return obj.Server.HTTPPassword
}

// ServerHTTPPort read HTTP Port options
func (obj *StorageST) ServerHTTPPort() string {
	obj.mutex.RLock()
	defer obj.mutex.RUnlock()
	return obj.Server.HTTPPort
}

// ServerRTSPPort read HTTP Port options
func (obj *StorageST) ServerRTSPPort() string {
	obj.mutex.RLock()
	defer obj.mutex.RUnlock()
	return obj.Server.RTSPPort
}

// ServerHTTPS read HTTPS Port options
func (obj *StorageST) ServerHTTPS() bool {
	obj.mutex.RLock()
	defer obj.mutex.RUnlock()
	return obj.Server.HTTPS
}

// ServerHTTPSPort read HTTPS Port options
func (obj *StorageST) ServerHTTPSPort() string {
	obj.mutex.RLock()
	defer obj.mutex.RUnlock()
	return obj.Server.HTTPSPort
}

// ServerHTTPSAutoTLSEnable read HTTPS Port options
func (obj *StorageST) ServerHTTPSAutoTLSEnable() bool {
	obj.mutex.RLock()
	defer obj.mutex.RUnlock()
	return obj.Server.HTTPSAutoTLSEnable
}

// ServerHTTPSAutoTLSName read HTTPS Port options
func (obj *StorageST) ServerHTTPSAutoTLSName() string {
	obj.mutex.RLock()
	defer obj.mutex.RUnlock()
	return obj.Server.HTTPSAutoTLSName
}

// ServerHTTPSCert read HTTPS Cert options
func (obj *StorageST) ServerHTTPSCert() string {
	obj.mutex.RLock()
	defer obj.mutex.RUnlock()
	return obj.Server.HTTPSCert
}

// ServerHTTPSKey read HTTPS Key options
func (obj *StorageST) ServerHTTPSKey() string {
	obj.mutex.RLock()
	defer obj.mutex.RUnlock()
	return obj.Server.HTTPSKey
}

// ServerICEServers read ICE servers
func (obj *StorageST) ServerICEServers() []string {
	obj.mutex.Lock()
	defer obj.mutex.Unlock()
	return obj.Server.ICEServers
}

// ServerICEServers read ICE username
func (obj *StorageST) ServerICEUsername() string {
	obj.mutex.Lock()
	defer obj.mutex.Unlock()
	return obj.Server.ICEUsername
}

// ServerICEServers read ICE credential
func (obj *StorageST) ServerICECredential() string {
	obj.mutex.Lock()
	defer obj.mutex.Unlock()
	return obj.Server.ICECredential
}

// ServerTokenEnable read HTTPS Key options
func (obj *StorageST) ServerTokenEnable() bool {
	obj.mutex.RLock()
	defer obj.mutex.RUnlock()
	return obj.Server.Token.Enable
}

// ServerTokenBackend read HTTPS Key options
func (obj *StorageST) ServerTokenBackend() string {
	obj.mutex.RLock()
	defer obj.mutex.RUnlock()
	return obj.Server.Token.Backend
}

// ServerWebRTCPortMin read WebRTC Port Min
func (obj *StorageST) ServerWebRTCPortMin() uint16 {
	obj.mutex.Lock()
	defer obj.mutex.Unlock()
	return obj.Server.WebRTCPortMin
}

// ServerWebRTCPortMax read WebRTC Port Max
func (obj *StorageST) ServerWebRTCPortMax() uint16 {
	obj.mutex.Lock()
	defer obj.mutex.Unlock()
	return obj.Server.WebRTCPortMax
}
