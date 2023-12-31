package main

import (
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/autotls"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// Message resp struct
type Message struct {
	Status  int         `json:"status"`
	Payload interface{} `json:"payload"`
}

// HTTPAPIServer start http server routes
func HTTPAPIServer() {
	//Set HTTP API mode
	log.WithFields(logrus.Fields{
		"module": "http_server",
		"func":   "RTSPServer",
		"call":   "Start",
	}).Infoln("Server HTTP start")
	var public *gin.Engine
	if !Storage.ServerHTTPDebug() {
		gin.SetMode(gin.ReleaseMode)
		public = gin.New()
	} else {
		gin.SetMode(gin.DebugMode)
		public = gin.Default()
	}

	public.Use(CrossOrigin())
	//Add private login password protect methods
	just_super := public.Group("/")
	just_admin := public.Group("/")
	together := public.Group("/")
	refresh := public.Group("/")
	privat := public.Group("/")
	just_super.Use(func(c *gin.Context) {
		token := c.Request.Header.Get("TokenSuper")
		token = RSA_OAEP_Decrypt(token, *FindPrivateKey(Storage.Server.Username))
		if CheckExpiredToken(token, (*Storage).Server.Username) {
			c.AbortWithStatusJSON(401, gin.H{
				"message": "Pls change your password and login again",
			})
			return
		}
		if time.Now().Unix() > Storage.CheckExpire() {
			SaveExpiredToken(Storage.CheckTokenSuper(), (*Storage).Server.Username)
			c.AbortWithStatusJSON(401, gin.H{
				"message": "Token expired",
			})
			return
		}
		if token == "" || token != Storage.CheckTokenSuper() {
			c.AbortWithStatusJSON(401, gin.H{
				"message": "Token incorrect",
			})
			return
		}
	})
	just_admin.Use(func(c *gin.Context) {
		token := c.Request.Header.Get("Token")
		token = RSA_OAEP_Decrypt(token, *FindPrivateKey((*Storage).Server.Username))
		if CheckExpiredToken(token, (*Storage).Server.Username) {
			c.AbortWithStatusJSON(401, gin.H{
				"message": "Pls change your password and login again",
			})
			return
		}
		if time.Now().Unix() > Storage.CheckExpire() {
			SaveExpiredToken(Storage.CheckToken(), (*Storage).Server.Username)
			c.AbortWithStatusJSON(401, gin.H{
				"message": "Token expired",
			})
			return
		}
		if token == "" || token != Storage.CheckToken() {
			c.AbortWithStatusJSON(401, gin.H{
				"message": "Token incorrect",
			})
			return
		}
	})
	together.Use(func(c *gin.Context) {
		token := c.Request.Header.Get("Token")
		token = RSA_OAEP_Decrypt(token, *FindPrivateKey((*Storage).Server.Username))
		if CheckExpiredToken(token, (*Storage).Server.Username) {
			c.AbortWithStatusJSON(401, gin.H{
				"message": "Pls change your password and login again",
			})
			return
		}
		if time.Now().Unix() > Storage.CheckExpire() {
			if Storage.CheckToken() != "" {
				SaveExpiredToken(Storage.CheckToken(), (*Storage).Server.Username)
			}
			if Storage.CheckTokenSuper() != "" {
				SaveExpiredToken(Storage.CheckTokenSuper(), (*Storage).Server.Username)
			}
			c.AbortWithStatusJSON(401, gin.H{
				"message": "Token expired",
			})
			return
		}
		if token == "" || (token != Storage.CheckToken() && token != Storage.CheckTokenSuper()) {
			c.AbortWithStatusJSON(401, gin.H{
				"message": "Token incorrect",
			})
			return
		}
	})
	refresh.Use(func(c *gin.Context) {
		token := c.Request.Header.Get("TokenRefresh")
		token = RSA_OAEP_Decrypt(token, *FindPrivateKey((*Storage).Server.Username))
		yourRT := FindRefreshToken((*Storage).Server.Username)
		if CheckExpiredRefreshToken(token, (*Storage).Server.Username) {
			c.AbortWithStatusJSON(401, gin.H{
				"message": "Pls change your password and login again",
			})
			return
		}
		if time.Now().Unix() > Storage.CheckRTExpire() {
			SaveExpiredRefreshToken(yourRT, (*Storage).Server.Username)
			c.AbortWithStatusJSON(401, gin.H{
				"message": "Token refresh expired! Pls login again",
			})
			return
		}
		if token == "" || token != yourRT {
			c.AbortWithStatusJSON(401, gin.H{
				"message": "Token refresh incorrect",
			})
			return
		}
	})
	/*
		Static HTML Files Demo Mode
	*/

	if Storage.ServerHTTPDemo() {
		public.LoadHTMLGlob(Storage.ServerHTTPDir() + "/templates/*")
		public.GET("/", HTTPAPIServerIndex)
		public.GET("/pages/stream/list", HTTPAPIStreamList)
		public.GET("/pages/stream/add", HTTPAPIAddStream)
		public.GET("/pages/stream/edit/:uuid", HTTPAPIEditStream)
		public.GET("/pages/player/hls/:uuid/:channel", HTTPAPIPlayHls)
		public.GET("/pages/player/mse/:uuid/:channel", HTTPAPIPlayMse)
		public.GET("/pages/player/webrtc/:uuid/:channel", HTTPAPIPlayWebrtc)
		public.GET("/pages/multiview", HTTPAPIMultiview)
		public.Any("/pages/multiview/full", HTTPAPIFullScreenMultiView)
		public.GET("/pages/documentation", HTTPAPIServerDocumentation)
		public.GET("/pages/player/all/:uuid/:channel", HTTPAPIPlayAll)
		public.StaticFS("/static", http.Dir(Storage.ServerHTTPDir()+"/static"))
	}

	public.POST("/role/add", AddRole)
	public.POST("/group/add", AddGroup)
	public.POST("/user/add", AddUser)
	public.POST("/user/edit", EditUser)
	public.GET("/user/delete", DeleteUser)
	public.GET("/user/list", ListUser)

	public.POST("/login", HTTPAPILogin)
	public.POST("/change/password", HTTPAPIChangePassword)
	public.GET("/streams", HTTPAPIServerStreams)
	public.POST("/stream/add", HTTPAPIServerStreamAdd)
	public.POST("/stream/edit", HTTPAPIServerStreamEdit)
	public.POST("/stream/delete", HTTPAPIServerStreamDelete)
	public.GET("/stream/reload", HTTPAPIServerStreamReload)
	public.GET("/stream/info", HTTPAPIServerStreamInfo)

	/*just_super.POST("/role/add", AddRole)
	just_super.POST("/group/add", AddGroup)
	just_super.POST("/user/add", AddUser)
	just_super.POST("/user/edit", EditUser)
	just_super.GET("/user/delete", DeleteUser)
	just_super.GET("/user/list", ListUser)

	public.POST("/login", HTTPAPILogin)

	refresh.POST("/take/token", HTTPAPITakeToken)
	together.POST("/change/password", HTTPAPIChangePassword)
	together.GET("/streams", HTTPAPIServerStreams)
	just_admin.POST("/stream/add", HTTPAPIServerStreamAdd)
	together.POST("/stream/edit", HTTPAPIServerStreamEdit)
	together.POST("/stream/delete", HTTPAPIServerStreamDelete)
	together.GET("/stream/reload", HTTPAPIServerStreamReload)
	together.GET("/stream/info", HTTPAPIServerStreamInfo)*/
	public.POST("/stream/:uuid/channel/:channel/webrtc", HTTPAPIServerStreamWebRTC)

	/*
		Streams Multi Control elements
	*/

	privat.POST("/streams/multi/control/add", HTTPAPIServerStreamsMultiControlAdd)
	privat.POST("/streams/multi/control/delete", HTTPAPIServerStreamsMultiControlDelete)

	/*
		Stream Channel elements
	*/

	privat.POST("/stream/:uuid/channel/:channel/add", HTTPAPIServerStreamChannelAdd)
	privat.POST("/stream/:uuid/channel/:channel/edit", HTTPAPIServerStreamChannelEdit)
	privat.GET("/stream/:uuid/channel/:channel/delete", HTTPAPIServerStreamChannelDelete)
	privat.GET("/stream/:uuid/channel/:channel/codec", HTTPAPIServerStreamChannelCodec)
	privat.GET("/stream/:uuid/channel/:channel/reload", HTTPAPIServerStreamChannelReload)
	privat.GET("/stream/:uuid/channel/:channel/info", HTTPAPIServerStreamChannelInfo)
	/*
		Stream video elements
	*/
	//HLS
	public.GET("/stream/:uuid/channel/:channel/hls/live/index.m3u8", HTTPAPIServerStreamHLSM3U8)
	public.GET("/stream/:uuid/channel/:channel/hls/live/segment/:seq/file.ts", HTTPAPIServerStreamHLSTS)
	//HLS remote record
	//public.GET("/stream/:uuid/channel/:channel/hls/rr/:s/:e/index.m3u8", HTTPAPIServerStreamRRM3U8)
	//public.GET("/stream/:uuid/channel/:channel/hls/rr/:s/:e/:seq/file.ts", HTTPAPIServerStreamRRTS)
	//HLS LL
	public.GET("/stream/:uuid/channel/:channel/hlsll/live/index.m3u8", HTTPAPIServerStreamHLSLLM3U8)
	public.GET("/stream/:uuid/channel/:channel/hlsll/live/init.mp4", HTTPAPIServerStreamHLSLLInit)
	public.GET("/stream/:uuid/channel/:channel/hlsll/live/segment/:segment/:any", HTTPAPIServerStreamHLSLLM4Segment)
	public.GET("/stream/:uuid/channel/:channel/hlsll/live/fragment/:segment/:fragment/:any", HTTPAPIServerStreamHLSLLM4Fragment)
	//MSE
	public.GET("/stream/:uuid/channel/:channel/mse", HTTPAPIServerStreamMSE)
	//Save fragment to mp4
	public.GET("/stream/:uuid/channel/:channel/save/mp4/fragment/:duration", HTTPAPIServerStreamSaveToMP4)
	/*
		HTTPS Mode Cert
		# Key considerations for algorithm "RSA" ≥ 2048-bit
		openssl genrsa -out server.key 2048

		# Key considerations for algorithm "ECDSA" ≥ secp384r1
		# List ECDSA the supported curves (openssl ecparam -list_curves)
		#openssl ecparam -genkey -name secp384r1 -out server.key
		#Generation of self-signed(x509) public key (PEM-encodings .pem|.crt) based on the private (.key)

		openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650
	*/
	if Storage.ServerHTTPS() {
		if Storage.ServerHTTPSAutoTLSEnable() {
			go func() {
				err := autotls.Run(public, Storage.ServerHTTPSAutoTLSName()+Storage.ServerHTTPSPort())
				if err != nil {
					log.Println("Start HTTPS Server Error", err)
				}
			}()
		} else {
			go func() {
				err := public.RunTLS(Storage.ServerHTTPSPort(), Storage.ServerHTTPSCert(), Storage.ServerHTTPSKey())
				if err != nil {
					log.WithFields(logrus.Fields{
						"module": "http_router",
						"func":   "HTTPSAPIServer",
						"call":   "ServerHTTPSPort",
					}).Fatalln(err.Error())
					os.Exit(1)
				}
			}()
		}
	}
	err := public.Run(Storage.ServerHTTPPort())
	if err != nil {
		log.WithFields(logrus.Fields{
			"module": "http_router",
			"func":   "HTTPAPIServer",
			"call":   "ServerHTTPPort",
		}).Fatalln(err.Error())
		os.Exit(1)
	}

}

// HTTPAPIServerIndex index file
func HTTPAPIServerIndex(c *gin.Context) {
	c.HTML(http.StatusOK, "index.tmpl", gin.H{
		"port":    Storage.ServerHTTPPort(),
		"streams": Storage.Streams,
		"version": time.Now().String(),
		"page":    "index",
	})

}

func HTTPAPIServerDocumentation(c *gin.Context) {
	c.HTML(http.StatusOK, "documentation.tmpl", gin.H{
		"port":    Storage.ServerHTTPPort(),
		"streams": Storage.Streams,
		"version": time.Now().String(),
		"page":    "documentation",
	})
}

func HTTPAPIStreamList(c *gin.Context) {
	c.HTML(http.StatusOK, "stream_list.tmpl", gin.H{
		"port":    Storage.ServerHTTPPort(),
		"streams": Storage.Streams,
		"version": time.Now().String(),
		"page":    "stream_list",
	})
}

func HTTPAPIPlayHls(c *gin.Context) {
	c.HTML(http.StatusOK, "play_hls.tmpl", gin.H{
		"port":    Storage.ServerHTTPPort(),
		"streams": Storage.Streams,
		"version": time.Now().String(),
		"page":    "play_hls",
		"uuid":    c.Param("uuid"),
		"channel": c.Param("channel"),
	})
}
func HTTPAPIPlayMse(c *gin.Context) {
	c.HTML(http.StatusOK, "play_mse.tmpl", gin.H{
		"port":    Storage.ServerHTTPPort(),
		"streams": Storage.Streams,
		"version": time.Now().String(),
		"page":    "play_mse",
		"uuid":    c.Param("uuid"),
		"channel": c.Param("channel"),
	})
}
func HTTPAPIPlayWebrtc(c *gin.Context) {
	c.HTML(http.StatusOK, "play_webrtc.tmpl", gin.H{
		"port":    Storage.ServerHTTPPort(),
		"streams": Storage.Streams,
		"version": time.Now().String(),
		"page":    "play_webrtc",
		"uuid":    c.Param("uuid"),
		"channel": c.Param("channel"),
	})
}
func HTTPAPIAddStream(c *gin.Context) {
	c.HTML(http.StatusOK, "add_stream.tmpl", gin.H{
		"port":    Storage.ServerHTTPPort(),
		"streams": Storage.Streams,
		"version": time.Now().String(),
		"page":    "add_stream",
	})
}
func HTTPAPIEditStream(c *gin.Context) {
	c.HTML(http.StatusOK, "edit_stream.tmpl", gin.H{
		"port":    Storage.ServerHTTPPort(),
		"streams": Storage.Streams,
		"version": time.Now().String(),
		"page":    "edit_stream",
		"uuid":    c.Param("uuid"),
	})
}

func HTTPAPIMultiview(c *gin.Context) {
	c.HTML(http.StatusOK, "multiview.tmpl", gin.H{
		"port":    Storage.ServerHTTPPort(),
		"streams": Storage.Streams,
		"version": time.Now().String(),
		"page":    "multiview",
	})
}

func HTTPAPIPlayAll(c *gin.Context) {
	c.HTML(http.StatusOK, "play_all.tmpl", gin.H{
		"port":    Storage.ServerHTTPPort(),
		"streams": Storage.Streams,
		"version": time.Now().String(),
		"page":    "play_all",
		"uuid":    c.Param("uuid"),
		"channel": c.Param("channel"),
	})
}

type MultiViewOptions struct {
	Grid   int                             `json:"grid"`
	Player map[string]MultiViewOptionsGrid `json:"player"`
}
type MultiViewOptionsGrid struct {
	UUID       string `json:"uuid"`
	Channel    int    `json:"channel"`
	PlayerType string `json:"playerType"`
}

func HTTPAPIFullScreenMultiView(c *gin.Context) {
	var createParams MultiViewOptions
	err := c.ShouldBindJSON(&createParams)
	if err != nil {
		log.WithFields(logrus.Fields{
			"module": "http_page",
			"func":   "HTTPAPIFullScreenMultiView",
			"call":   "BindJSON",
		}).Errorln(err.Error())
	}
	log.WithFields(logrus.Fields{
		"module": "http_page",
		"func":   "HTTPAPIFullScreenMultiView",
		"call":   "Options",
	}).Debugln(createParams)
	c.HTML(http.StatusOK, "fullscreenmulti.tmpl", gin.H{
		"port":    Storage.ServerHTTPPort(),
		"streams": Storage.Streams,
		"version": time.Now().String(),
		"options": createParams,
		"page":    "fullscreenmulti",
		"query":   c.Request.URL.Query(),
	})
}

// CrossOrigin Access-Control-Allow-Origin any methods
func CrossOrigin() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}
