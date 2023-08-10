package main

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

func AddGroup(c *gin.Context) {
	var payload Group
	c.BindJSON(&payload)
	if CheckGroupIDEXIST(payload.IDGroup) {
		c.AbortWithStatusJSON(500, gin.H{
			"message": "Group id already exists",
		})
		return
	}
	if payload.NameGroup == "" || payload.IDGroup == "" {
		c.AbortWithStatusJSON(500, gin.H{
			"message": "Lack of information",
		})
		return
	} else {
		col := client.Database("RTSP-WEB").Collection("Group")
		col.InsertOne(ctx, payload)
		c.IndentedJSON(200, Message{Status: 1, Payload: Success})
	}
}
func AddRole(c *gin.Context) {
	var payload Role
	c.BindJSON(&payload)
	if payload.IDRole == "" || payload.LevelRole == "" {
		c.AbortWithStatusJSON(500, gin.H{
			"message": "Lack of information",
		})
		return
	}
	if payload.IDRole == "0" && payload.LevelRole != "super_user" {
		c.AbortWithStatusJSON(500, gin.H{
			"message": "just only one super user",
		})
		return
	}
	if payload.IDRole != "0" && payload.LevelRole == "super_user" {
		c.AbortWithStatusJSON(500, gin.H{
			"message": "super user must have role id 0",
		})
		return
	}
	if CheckRoleLevelEXIST(payload.LevelRole) {
		c.AbortWithStatusJSON(500, gin.H{
			"message": "Role level already exists",
		})
		return
	}
	if CheckRoleIDEXIST(payload.IDRole) {
		c.AbortWithStatusJSON(500, gin.H{
			"message": "Role id already exists",
		})
		return
	}
	if payload.LevelRole == "" {
		c.AbortWithStatusJSON(500, gin.H{
			"message": "Lack of information",
		})
		return
	} else {
		col := client.Database("RTSP-WEB").Collection("Role")
		col.InsertOne(ctx, payload)
		c.IndentedJSON(200, Message{Status: 1, Payload: Success})
	}
}
func AddUser(c *gin.Context) {
	var payload User
	c.BindJSON(&payload)
	if payload.Username == "" || payload.Password == "" || payload.GroupID == "" || payload.RoleLevel == "" {
		c.AbortWithStatusJSON(500, gin.H{
			"message": "Lack of information",
		})
		return
	}
	checkRoleLevel := CheckRoleLevel(payload.RoleLevel)
	if checkRoleLevel == "0" || payload.Username == "super_user" {
		c.AbortWithStatusJSON(500, gin.H{
			"message": "Just only one super_user",
		})
		return
	} else if checkRoleLevel != "0" {
		if checkRoleLevel == "" {
			c.AbortWithStatusJSON(500, gin.H{
				"message": "Role Level incorrect",
			})
			return
		}
		if CheckUsernameEXIST(payload.Username) {
			c.AbortWithStatusJSON(500, gin.H{
				"message": "Username already exists",
			})
			return
		}
		if !CheckGroupIDEXIST(payload.GroupID) {
			c.AbortWithStatusJSON(500, gin.H{
				"message": "Group id does not exists",
			})
			return
		}
		if !CheckRoleLevelEXIST(payload.RoleLevel) {
			c.AbortWithStatusJSON(500, gin.H{
				"message": "Role level does not exists",
			})
			return
		}
	}
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
	payload.Password = string(hashedPassword)
	col := client.Database("RTSP-WEB").Collection("USER")
	col.InsertOne(ctx, payload)

	var blackList token_Expired
	blackList.Username = payload.Username
	blackList.TokenExpired = ""
	col = client.Database("RTSP-WEB").Collection("Blacklist_Token")
	col.InsertOne(ctx, blackList)

	c.IndentedJSON(200, Message{Status: 1, Payload: Success})
}
func EditUser(c *gin.Context) {
	var payload User
	c.BindJSON(&payload)
	username := payload.Username
	if !CheckRoleLevelEXIST(payload.RoleLevel) && payload.RoleLevel != "" {
		c.AbortWithStatusJSON(500, gin.H{
			"message": "Role level does not exists",
		})
		return
	}
	if !CheckGroupIDEXIST(payload.GroupID) && payload.GroupID != "" {
		c.AbortWithStatusJSON(500, gin.H{
			"message": "Group id does not exists",
		})
		return
	}
	if CheckRoleLevel(payload.RoleLevel) == "0" || payload.Username == "super_user" {
		c.AbortWithStatusJSON(500, gin.H{
			"message": "just only one super user",
		})
		return
	}
	col := client.Database("RTSP-WEB").Collection("USER")
	if !CheckUsernameofEdit(username, &payload) {
		c.AbortWithStatusJSON(500, gin.H{
			"message": "Username not found",
		})
		return
	}
	filter := bson.D{primitive.E{Key: "username", Value: username}}
	col.ReplaceOne(context.TODO(), filter, payload)
	c.IndentedJSON(200, Message{Status: 1, Payload: Success})
}
func DeleteUser(c *gin.Context) {
	var payload FindUsername
	c.BindJSON(&payload)
	username := payload.Username
	col := client.Database("RTSP-WEB").Collection("USER")
	if !CheckUsernameofFind(username) {
		c.AbortWithStatusJSON(500, gin.H{
			"message": "Username not found",
		})
		return
	}
	if CheckRoleLevel(CheckUsernameDelete(payload.Username)) == "0" {
		c.AbortWithStatusJSON(500, gin.H{
			"message": "You cant delete super user",
		})
		return
	}
	filter := bson.D{primitive.E{Key: "username", Value: username}}
	col.DeleteOne(ctx, filter)
	c.IndentedJSON(200, Message{Status: 1, Payload: Success})
}
func ListUser(c *gin.Context) {
	col := client.Database("RTSP-WEB").Collection("USER")
	var results []bson.M
	filter := bson.D{primitive.E{Key: "username", Value: bson.D{{"$exists", true}}}}
	cursor, _ := col.Find(ctx, filter)
	defer cursor.Close(ctx)
	if !cursor.Next(ctx) {
		c.IndentedJSON(200, "no results found")
		return
	}
	c.JSON(200, "data in mongoDB")
	cursor.All(ctx, &results)
	var end User
	for _, doc := range results {
		if user_name, ok := doc["username"].(string); ok {
			end.Username = user_name
		}
		if password, ok := doc["password"].(string); ok {
			end.Password = password
		}
		if groupID, ok := doc["group_id"].(string); ok {
			end.GroupID = groupID
		}
		if roleLevel, ok := doc["role_level"].(string); ok {
			end.RoleLevel = roleLevel
		}
		c.IndentedJSON(200, end)
	}
}
func HTTPAPILogin(c *gin.Context) {
	var payload UserLogin
	c.BindJSON(&payload)
	checkUserNameLoggin := CheckUsernameLoggin(payload.Username, payload.Password)
	if checkUserNameLoggin == "" {
		c.AbortWithStatusJSON(500, gin.H{
			"message": "Username or password incorrect",
		})
		return
	}
	if payload.Username == "super_user" && payload.Password == "super_user" {
		Storage.SaveUsername(payload.Username)
		Storage.SaveRoleLevel(checkUserNameLoggin)
		Storage.SaveRoleID(c, "0")
		Storage.CreateRefreshToken(c, payload.Username)
		Storage.CreateTokenSuper(c, Storage.Server.publicKey)
	} else {
		Storage.SaveUsername(payload.Username)
		Storage.SaveRoleLevel(checkUserNameLoggin)
		Storage.SaveRoleID(c, CheckRoleLevel(checkUserNameLoggin))
		Storage.SaveGroupID(payload.Username)
		Storage.CreateRefreshToken(c, payload.Username)
		Storage.CreateToken(c, Storage.Server.publicKey)
	}
}
func HTTPAPITakeToken(c *gin.Context) {
	if (*Storage).Server.Username == "super_user" {
		Storage.CreateTokenSuper(c, (Storage).Server.publicKey)
	} else {
		Storage.CreateToken(c, (Storage).Server.publicKey)
	}
}
func HTTPAPIChangePassword(c *gin.Context) {
	var payload ChangePassword
	c.BindJSON(&payload)
	OldPass := payload.Old_Password
	NewPass := payload.New_Password
	/**/
	col := client.Database("RTSP-WEB").Collection("USER")
	/***/
	filter := bson.D{primitive.E{Key: "username", Value: (*Storage).UsernameForStream()}}
	if !(*Storage).CheckOldPassword((*Storage).UsernameForStream(), OldPass) {
		c.AbortWithStatusJSON(500, gin.H{
			"message": "Old password incorrect",
		})
		return
	}
	cursor, _ := col.Find(ctx, filter)
	defer cursor.Close(ctx)
	if !cursor.Next(ctx) {
		c.IndentedJSON(200, "no results found")
		return
	}
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(NewPass), bcrypt.DefaultCost)
	NewPass = string(hashedPassword)
	var results []bson.M
	cursor.All(ctx, &results)
	var end User
	for _, doc := range results {
		if _, ok := doc["password"].(string); ok {
			end.Password = NewPass
		}
		if username, ok := doc["username"].(string); ok {
			end.Username = username
		}
		if group_id, ok := doc["group_id"].(string); ok {
			end.GroupID = group_id
		}
		if role_level, ok := doc["role_level"].(string); ok {
			end.RoleLevel = role_level
		}
		if privateKey, ok := doc["private_key"].(primitive.Binary); ok {
			end.PrivateKey = privateKey
		}
	}
	(*Storage).ChangePassword()
	col.ReplaceOne(context.TODO(), filter, end)
	c.IndentedJSON(200, Message{Status: 1, Payload: Success})
}

// HTTPAPIServerStreams function return stream list
func HTTPAPIServerStreams(c *gin.Context) {
	id_group := (*Storage).GroupIDForStream()
	_, err := Storage.MarshalledStreamsList()
	if err != nil {
		c.IndentedJSON(500, Message{Status: 0, Payload: err.Error()})
		return
	}
	col := client.Database("RTSP-WEB").Collection("StreamOfUser")
	var results []bson.M
	if (*Storage).CheckRoleInfo() {
		filter := bson.D{primitive.E{Key: "group_id", Value: bson.D{{"$exists", true}}}}
		cursor, _ := col.Find(ctx, filter)
		defer cursor.Close(ctx)
		if !cursor.Next(ctx) {
			c.IndentedJSON(200, "no results found")
			return
		}
		c.JSON(200, "data in mongoDB")
		cursor.All(ctx, &results)
		var end StreamST
		for _, doc := range results {
			if user_name, ok := doc["username"].(string); ok {
				end.Username = user_name
			}
			if uuid, ok := doc["uuid"].(string); ok {
				end.UUID = uuid
			}
			if groupID, ok := doc["group_id"].(string); ok {
				end.GroupID = groupID
			}
			if roleLevel, ok := doc["role_level"].(string); ok {
				end.RoleLevel = roleLevel
			}
			if name, ok := doc["name"].(string); ok {
				end.Name = name
			}
			c.IndentedJSON(200, end)
		}
		return
	}
	filter := bson.D{primitive.E{Key: "group_id", Value: id_group}}
	cursor, _ := col.Find(ctx, filter)
	if !cursor.Next(ctx) {
		c.IndentedJSON(200, "no results found")
		return
	}
	c.JSON(200, "data in mongoDB")
	cursor.All(ctx, &results)
	var end StreamST
	for _, doc := range results {
		if user_name, ok := doc["username"].(string); ok {
			end.Username = user_name
		}
		if uuid, ok := doc["uuid"].(string); ok {
			end.UUID = uuid
		}
		if GroupID, ok := doc["group_id"].(string); ok {
			end.GroupID = GroupID
		}
		if roleLevel, ok := doc["role_level"].(string); ok {
			end.RoleLevel = roleLevel
		}
		if Name, ok := doc["name"].(string); ok {
			end.Name = Name
		}
		c.IndentedJSON(200, end)
	}
}

// HTTPAPIServerStreamsMultiControlAdd function add new stream's
func HTTPAPIServerStreamsMultiControlAdd(c *gin.Context) {
	requestLogger := log.WithFields(logrus.Fields{
		"module": "http_stream",
		"func":   "HTTPAPIServerStreamsMultiControlAdd",
	})

	var payload StorageST
	err := c.BindJSON(&payload)
	if err != nil {
		c.IndentedJSON(400, Message{Status: 0, Payload: err.Error()})
		requestLogger.WithFields(logrus.Fields{
			"call": "BindJSON",
		}).Errorln(err.Error())
		return
	}
	if payload.Streams == nil || len(payload.Streams) < 1 {
		c.IndentedJSON(400, Message{Status: 0, Payload: ErrorStreamsLen0.Error()})
		requestLogger.WithFields(logrus.Fields{
			"call": "len(payload)",
		}).Errorln(ErrorStreamsLen0.Error())
		return
	}
	var resp = make(map[string]Message)
	var FoundError bool
	for k, v := range payload.Streams {
		err = Storage.StreamAdd(k, v)
		if err != nil {
			requestLogger.WithFields(logrus.Fields{
				"stream": k,
				"call":   "StreamAdd",
			}).Errorln(err.Error())
			resp[k] = Message{Status: 0, Payload: err.Error()}
			FoundError = true
		} else {
			resp[k] = Message{Status: 1, Payload: Success}
		}
	}
	if FoundError {
		c.IndentedJSON(200, Message{Status: 0, Payload: resp})
	} else {
		c.IndentedJSON(200, Message{Status: 1, Payload: resp})
	}
}

// HTTPAPIServerStreamsMultiControlDelete function delete stream's
func HTTPAPIServerStreamsMultiControlDelete(c *gin.Context) {
	requestLogger := log.WithFields(logrus.Fields{
		"module": "http_stream",
		"func":   "HTTPAPIServerStreamsMultiControlDelete",
	})

	var payload []string
	err := c.BindJSON(&payload)
	if err != nil {
		c.IndentedJSON(400, Message{Status: 0, Payload: err.Error()})
		requestLogger.WithFields(logrus.Fields{
			"call": "BindJSON",
		}).Errorln(err.Error())
		return
	}
	if len(payload) < 1 {
		c.IndentedJSON(400, Message{Status: 0, Payload: ErrorStreamsLen0.Error()})
		requestLogger.WithFields(logrus.Fields{
			"call": "len(payload)",
		}).Errorln(ErrorStreamsLen0.Error())
		return
	}
	var resp = make(map[string]Message)
	var FoundError bool
	for _, key := range payload {
		err := Storage.StreamDelete(key)
		if err != nil {
			requestLogger.WithFields(logrus.Fields{
				"stream": key,
				"call":   "StreamDelete",
			}).Errorln(err.Error())
			resp[key] = Message{Status: 0, Payload: err.Error()}
			FoundError = true
		} else {
			resp[key] = Message{Status: 1, Payload: Success}
		}
	}
	if FoundError {
		c.IndentedJSON(200, Message{Status: 0, Payload: resp})
	} else {
		c.IndentedJSON(200, Message{Status: 1, Payload: resp})
	}
}

// HTTPAPIServerStreamAdd function add new stream
func HTTPAPIServerStreamAdd(c *gin.Context) {
	var payload StreamST
	err := c.BindJSON(&payload)
	uuid := payload.UUID
	payload.Username = (*Storage).UsernameForStream()
	if payload.RoleLevel == "" {
		payload.RoleLevel = (*Storage).RoleLevelForStream()
	}
	payload.GroupID = (*Storage).GroupIDForStream()
	if err != nil {
		c.IndentedJSON(400, Message{Status: 0, Payload: err.Error()})
		log.WithFields(logrus.Fields{
			"module": "http_stream",
			"stream": uuid,
			"func":   "HTTPAPIServerStreamAdd",
			"call":   "BindJSON",
		}).Errorln(err.Error())
		return
	}

	err = Storage.StreamAdd(uuid, payload)
	if err != nil {
		c.IndentedJSON(500, Message{Status: 0, Payload: err.Error()})
		log.WithFields(logrus.Fields{
			"module": "http_stream",
			"stream": uuid,
			"func":   "HTTPAPIServerStreamAdd",
			"call":   "StreamAdd",
		}).Errorln(err.Error())
		return
	}
	col := client.Database("RTSP-WEB").Collection("StreamOfUser")
	col.InsertOne(ctx, payload)
	c.IndentedJSON(200, Message{Status: 1, Payload: Success})
}

// HTTPAPIServerStreamEdit function edit stream
func HTTPAPIServerStreamEdit(c *gin.Context) {
	var payload StreamST
	err := c.BindJSON(&payload)
	uuid := payload.UUID
	if err != nil {
		c.IndentedJSON(400, Message{Status: 0, Payload: err.Error()})
		log.WithFields(logrus.Fields{
			"module": "http_stream",
			"stream": uuid,
			"func":   "HTTPAPIServerStreamEdit",
			"call":   "BindJSON",
		}).Errorln(err.Error())
		return
	}
	if payload.Username == "" || payload.GroupID == "" {
		c.AbortWithStatusJSON(500, gin.H{
			"message": "You must fill the username and group id",
		})
		return
	}
	col := client.Database("RTSP-WEB").Collection("StreamOfUser")
	if CheckUUIDofFind(uuid) == "" {
		c.AbortWithStatusJSON(500, gin.H{
			"message": "UUID not found! You are not allowed to change the UUID",
		})
		return
	} else {
		if payload.Username != CheckUUIDofStreamForUser(uuid) {
			c.AbortWithStatusJSON(500, gin.H{
				"message": "You cant change username or your uuid incorrect",
			})
			return
		}
		if !(*Storage).CheckRoleInfo() {
			if (*Storage).GroupIDForStream() != CheckGroupIDForEditOrDelete(uuid) {
				c.AbortWithStatusJSON(500, gin.H{
					"message": "Not in the same group",
				})
				return
			}
		}
		if payload.GroupID != CheckGroupIDForEditOrDelete(payload.UUID) {
			c.AbortWithStatusJSON(500, gin.H{
				"message": "you cant change group id",
			})
			return
		}
		checkRoleLevel := CheckRoleLevel(payload.RoleLevel)
		if checkRoleLevel == "" {
			c.AbortWithStatusJSON(500, gin.H{
				"message": "RoleLevel incorrect",
			})
			return
		}
		if checkRoleLevel == "0" {
			c.AbortWithStatusJSON(500, gin.H{
				"message": "Role: Super invalid",
			})
			return
		}
		if !(*Storage).CheckRoleEdit(CheckUUIDForEditOrDelete(uuid), payload.RoleLevel) {
			c.AbortWithStatusJSON(500, gin.H{
				"message": "you cant edit this stream",
			})
			return
		}
	}
	filter := bson.D{primitive.E{Key: "uuid", Value: uuid}}
	col.ReplaceOne(context.TODO(), filter, payload)
	errr := Storage.StreamEdit(uuid, payload)
	if errr != nil {
		c.IndentedJSON(500, Message{Status: 0, Payload: err.Error()})
		log.WithFields(logrus.Fields{
			"module": "http_stream",
			"stream": uuid,
			"func":   "HTTPAPIServerStreamEdit",
			"call":   "StreamEdit",
		}).Errorln(err.Error())
		return
	}
	c.IndentedJSON(200, Message{Status: 1, Payload: Success})
}

// HTTPAPIServerStreamDelete function delete stream
func HTTPAPIServerStreamDelete(c *gin.Context) {
	var payload FindUUID
	c.BindJSON(&payload)
	uuid := payload.UUID
	col := client.Database("RTSP-WEB").Collection("StreamOfUser")
	if CheckUUIDofFind(uuid) == "" {
		c.AbortWithStatusJSON(500, gin.H{
			"message": "UUID not found",
		})
		return
	} else {
		if !(*Storage).CheckRoleInfo() {
			if (*Storage).GroupIDForStream() != CheckGroupIDForEditOrDelete(uuid) {
				c.AbortWithStatusJSON(500, gin.H{
					"message": "Not in the same group",
				})
				return
			}
			if !(*Storage).CheckRoleDeleteOrInfo(CheckUUIDForEditOrDelete(uuid)) {
				c.AbortWithStatusJSON(500, gin.H{
					"message": "you cant delete this stream",
				})
				return
			}
		}
	}
	filter := bson.D{primitive.E{Key: "uuid", Value: uuid}}
	col.DeleteOne(ctx, filter)
	errr := Storage.StreamDelete(uuid)
	if errr != nil {
		c.IndentedJSON(500, Message{Status: 0, Payload: errr.Error()})
		log.WithFields(logrus.Fields{
			"module": "http_stream",
			"stream": uuid,
			"func":   "HTTPAPIServerStreamDelete",
			"call":   "StreamDelete",
		}).Errorln(errr.Error())
		return
	}
	c.IndentedJSON(200, Message{Status: 1, Payload: Success})
}

// HTTPAPIServerStreamDelete function reload stream
func HTTPAPIServerStreamReload(c *gin.Context) {
	var payload FindUUID
	uuid := payload.UUID
	err := Storage.StreamReload(uuid)
	if err != nil {
		c.IndentedJSON(500, Message{Status: 0, Payload: err.Error()})
		log.WithFields(logrus.Fields{
			"module": "http_stream",
			"stream": uuid,
			"func":   "HTTPAPIServerStreamReload",
			"call":   "StreamReload",
		}).Errorln(err.Error())
		return
	}
	c.IndentedJSON(200, Message{Status: 1, Payload: Success})
}

// HTTPAPIServerStreamInfo function return stream info struct
func HTTPAPIServerStreamInfo(c *gin.Context) {
	var payload FindUUID
	c.BindJSON(&payload)
	uuid := payload.UUID
	check := CheckUUIDForEditOrDelete(uuid)
	if check == "" {
		c.AbortWithStatusJSON(500, gin.H{
			"message": "UUID not found",
		})
		return
	}
	if !(*Storage).CheckRoleInfo() {
		if (*Storage).GroupIDForStream() != CheckGroupIDForEditOrDelete(uuid) {
			c.AbortWithStatusJSON(500, gin.H{
				"message": "Not in the same group",
			})
			return
		}
		if !(*Storage).CheckRoleDeleteOrInfo(check) {
			c.AbortWithStatusJSON(500, gin.H{
				"message": "you cant show this stream",
			})
			return
		}
	}
	_, err := Storage.StreamInfo(uuid)
	if err != nil {
		c.IndentedJSON(500, Message{Status: 0, Payload: err.Error()})
		log.WithFields(logrus.Fields{
			"module": "http_stream",
			"stream": uuid,
			"func":   "HTTPAPIServerStreamInfo",
			"call":   "StreamInfo",
		}).Errorln(err.Error())
	}
	col := client.Database("RTSP-WEB").Collection("StreamOfUser")
	var result []bson.M
	filter := bson.D{primitive.E{Key: "uuid", Value: uuid}}
	cursor, _ := col.Find(ctx, filter)
	if !cursor.Next(ctx) {
		c.IndentedJSON(200, "no results found")
		return
	}
	c.JSON(200, "data in mongoDB")
	cursor.All(ctx, &result)
	c.IndentedJSON(200, Message{Status: 1, Payload: result})
}
