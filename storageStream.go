package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/liip/sheriff"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

func CreateIndexUSER() {
	// Create index model
	indexModel := mongo.IndexModel{
		Keys:    bson.D{{"username", 1}},
		Options: options.Index().SetName("index_name"),
	}

	// Create index on collection
	collection := client.Database("RTSP").Collection("USER")
	collection.Indexes().CreateOne(context.Background(), indexModel)
}
func CreateIndexRole() {
	// Create index model
	indexModel := mongo.IndexModel{
		Keys:    bson.D{{"level_role", 1}},
		Options: options.Index().SetName("index_name"),
	}

	// Create index on collection
	collection := client.Database("RTSP").Collection("Role")
	collection.Indexes().CreateOne(context.Background(), indexModel)
}
func CreateIndexGroup() {
	// Create index model
	indexModel := mongo.IndexModel{
		Keys:    bson.D{{"id_group", 1}},
		Options: options.Index().SetName("index_name"),
	}

	// Create index on collection
	collection := client.Database("RTSP").Collection("Group")
	collection.Indexes().CreateOne(context.Background(), indexModel)
}
func CreateIndexStream() {
	// Create index model
	indexModel := mongo.IndexModel{
		Keys:    bson.D{{"uuid", 1}},
		Options: options.Index().SetName("index_name"),
	}

	// Create index on collection
	collection := client.Database("RTSP").Collection("StreamOfUser")
	collection.Indexes().CreateOne(context.Background(), indexModel)
}
func CreateIndexBlackList() {
	// Create index model
	indexModel := mongo.IndexModel{
		Keys:    bson.D{{"username", 1}},
		Options: options.Index().SetName("index_name"),
	}

	// Create index on collection
	collection := client.Database("RTSP").Collection("Blacklist_Token")
	collection.Indexes().CreateOne(context.Background(), indexModel)
}
func CheckExpiredToken(tokenExpired string, username string) bool {
	col := client.Database("RTSP").Collection("Blacklist_Token")
	var results []bson.M
	filter := bson.D{primitive.E{Key: "username", Value: username}}
	cursor, _ := col.Find(ctx, filter)
	defer cursor.Close(ctx)
	cursor.All(ctx, &results)
	for _, doc := range results {
		token_Expired_data := doc["tokenexpired"]
		if tokenExpired == token_Expired_data {
			return true
		}
	}
	return false
}
func CheckExpiredRefreshToken(tokenExpired string, username string) bool {
	col := client.Database("RTSP").Collection("Blacklist_Token")
	var results []bson.M
	filter := bson.D{primitive.E{Key: "username", Value: username}}
	cursor, _ := col.Find(ctx, filter)
	defer cursor.Close(ctx)
	cursor.All(ctx, &results)
	for _, doc := range results {
		token_Expired_data := doc["token_refresh_expired"]
		if tokenExpired == token_Expired_data {
			return true
		}
	}
	return false
}
func SaveExpiredToken(tokenExpired string, username string) {
	var payload token_Expired
	payload.Username = username
	payload.TokenExpired = tokenExpired
	col := client.Database("RTSP").Collection("Blacklist_Token")
	cur, err := col.Find(ctx, bson.M{"username": username})
	if err != nil {
		log.Fatal(err)
	}

	var results []bson.M
	if err = cur.All(ctx, &results); err != nil {
		log.Fatal(err)
	}
	if len(results) == 0 {
		col.InsertOne(ctx, payload)
	} else {
		filter := bson.D{primitive.E{Key: "username", Value: username}}
		update := bson.D{{"$set", bson.D{{"tokenexpired", tokenExpired}}}}
		col.UpdateOne(context.TODO(), filter, update)
	}
}
func SaveExpiredRefreshToken(tokenExpired string, username string) {
	var payload token_Expired
	payload.Username = username
	payload.token_refresh_expired = tokenExpired
	col := client.Database("RTSP").Collection("Blacklist_Token")
	cur, err := col.Find(ctx, bson.M{"username": username})
	if err != nil {
		log.Fatal(err)
	}

	var results []bson.M
	if err = cur.All(ctx, &results); err != nil {
		log.Fatal(err)
	}
	if len(results) == 0 {
		col.InsertOne(ctx, payload)
	} else {
		filter := bson.D{primitive.E{Key: "username", Value: username}}
		update := bson.D{{"$set", bson.D{{"token_refresh_expired", tokenExpired}}}}
		col.UpdateOne(context.TODO(), filter, update)
	}
}

/*
tạo token cho super user
*/
func RSA_OAEP_Encrypt(secretMessage string, key rsa.PublicKey) string {
	label := []byte("OAEP Encrypted")
	rng := rand.Reader
	ciphertext, _ := rsa.EncryptOAEP(sha256.New(), rng, &key, []byte(secretMessage), label)
	return base64.StdEncoding.EncodeToString(ciphertext)
}
func RSA_OAEP_Decrypt(cipherText string, privKey rsa.PrivateKey) string {
	ct, _ := base64.StdEncoding.DecodeString(cipherText)
	label := []byte("OAEP Encrypted")
	rng := rand.Reader
	plaintext, _ := rsa.DecryptOAEP(sha256.New(), rng, &privKey, ct, label)
	return string(plaintext)
}
func (obj *StorageST) CreateRefreshToken(c *gin.Context, username string) {
	//create refresh token
	obj.mutex.Lock()
	defer obj.mutex.Unlock()
	privateKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	SavePrivateKey(privateKey, username)
	publicKey := privateKey.PublicKey
	obj.Server.publicKey = publicKey
	tokenRefesh := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Issuer:    "super",
		ExpiresAt: time.Now().Add(time.Hour * 240).Unix(),
	})
	obj.Server.RTexpiresAt = tokenRefesh.Claims.(jwt.StandardClaims).ExpiresAt
	tokenRefreshCreated, _ := tokenRefesh.SignedString([]byte(os.Getenv("JWT_SECRET_REFRESH")))
	obj.Server.tokenRefesh = tokenRefreshCreated

	tokenRefreshS := RSA_OAEP_Encrypt(tokenRefreshCreated, publicKey)
	c.String(200, "tokenRefresh: "+tokenRefreshS)
	col := client.Database("RTSP").Collection("USER")
	/***/
	filter := bson.D{primitive.E{Key: "username", Value: username}}
	update := bson.D{{"$set", bson.D{{"refresh_token", tokenRefreshS}}}}
	col.UpdateOne(ctx, filter, update)
}
func FindRefreshToken(username string) string {
	col := client.Database("RTSP").Collection("USER")
	cur, _ := col.Find(ctx, bson.M{"username": username})
	var results []bson.M
	if err := cur.All(ctx, &results); err != nil {
		log.Fatal(err)
	}
	for _, doc := range results {
		refresh_token := doc["refresh_token"].(string)
		refresh_token = RSA_OAEP_Decrypt(refresh_token, *FindPrivateKey((*Storage).Server.Username))
		return refresh_token
	}
	return ""
}
func (obj *StorageST) CreateTokenSuper(c *gin.Context, publicKey rsa.PublicKey) {
	obj.mutex.Lock()
	defer obj.mutex.Unlock()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Issuer:    "super",
		ExpiresAt: time.Now().Add(time.Minute * 1).Unix(),
	})
	obj.Server.expiresAt = token.Claims.(jwt.StandardClaims).ExpiresAt
	tokenCreated, _ := token.SignedString([]byte(os.Getenv("JWT_SECRET_SUPER")))
	obj.Server.tokenStringSuper = tokenCreated

	tokenS := RSA_OAEP_Encrypt(tokenCreated, publicKey)
	c.String(200, "\ntoken: "+tokenS)

	obj.Server.tokenString = ""
	key := "tokenSuper"
	value := tokenS
	rdb.HSet("TokenSuper", key, value)
}

/*
tạo token cho các role khác
*/
func (obj *StorageST) CreateToken(c *gin.Context, publicKey rsa.PublicKey) {
	obj.mutex.Lock()
	defer obj.mutex.Unlock()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Issuer:    "admin",
		ExpiresAt: time.Now().Add(time.Minute * 1).Unix(),
	})
	obj.Server.expiresAt = token.Claims.(jwt.StandardClaims).ExpiresAt
	tokenCreated, _ := token.SignedString([]byte(os.Getenv("JWT_SECRET")))

	obj.Server.tokenString = tokenCreated

	tokenS := RSA_OAEP_Encrypt(tokenCreated, publicKey)

	c.String(200, " \ntoken: "+tokenS)
	obj.Server.tokenStringSuper = ""
	key := "token"
	value := tokenS
	rdb.HSet("Token", key, value)
}
func (obj *StorageST) ChangePassword() {
	obj.Server.RTexpiresAt = 0
	obj.Server.expiresAt = 0
}

func SavePrivateKey(privateKey *rsa.PrivateKey, username string) {
	col := client.Database("RTSP").Collection("USER")
	filter := bson.D{primitive.E{Key: "username", Value: username}}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBinary := primitive.Binary{Data: privateKeyBytes}
	update := bson.D{{"$set", bson.D{{"private_key", privateKeyBinary}}}}
	col.UpdateOne(ctx, filter, update)
}
func FindPrivateKey(username string) *rsa.PrivateKey {
	col := client.Database("RTSP").Collection("USER")
	cur, _ := col.Find(ctx, bson.M{"username": username})
	var results []bson.M
	if err := cur.All(ctx, &results); err != nil {
		log.Fatal(err)
	}
	for _, doc := range results {
		privateKeyBinary := doc["private_key"].(primitive.Binary)
		privateKeyBytes := privateKeyBinary.Data
		base64.StdEncoding.EncodeToString(privateKeyBytes)
		privateKey, _ := x509.ParsePKCS1PrivateKey(privateKeyBytes)
		return privateKey
	}
	return nil
}

func addSuperUser() {
	col := client.Database("RTSP").Collection("USER")
	cur, err := col.Find(context.TODO(), bson.M{"username": "super_user"})

	if err != nil {
		log.Fatal(err)
	}

	var results []bson.M
	if err = cur.All(ctx, &results); err != nil {
		log.Fatal(err)
	}
	if len(results) == 0 {
		var payload User
		payload.Username = "super_user"
		payload.Password = "super_user"
		payload.RoleLevel = "super_user"
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
		payload.Password = string(hashedPassword)
		col.InsertOne(ctx, payload)
	}
}
func AddRoleSuperUser() {
	col := client.Database("RTSP").Collection("Role")
	cur, err := col.Find(ctx, bson.M{"level_role": "super_user"})
	if err != nil {
		log.Fatal(err)
	}

	var results []bson.M
	if err = cur.All(ctx, &results); err != nil {
		log.Fatal(err)
	}
	if len(results) == 0 {
		var payload Role
		payload.IDRole = "0"
		payload.LevelRole = "super_user"
		col.InsertOne(ctx, payload)
	}
}

/*
kiểm tra role  level superuser add vào có hợp lệ hay không, return role id
*/
func CheckRoleLevel(level_role string) string {
	col := client.Database("RTSP").Collection("Role")
	cur, err := col.Find(ctx, bson.M{"level_role": level_role})
	if err != nil {
		log.Fatal(err)
	}

	var results []bson.M
	if err = cur.All(ctx, &results); err != nil {
		log.Fatal(err)
	}
	if len(results) == 0 {
		return ""
	} else {
		for _, doc := range results {
			id_role := doc["id_role"].(string)
			return id_role
		}
	}
	return ""
}

/*
thực hiện việc lưu roleID và role level của người dùng khi họ login
mục đích gán vào stream khi người dùng add stream, tránh việc phải nhập lại
*/
func (obj *StorageST) SaveRoleID(c *gin.Context, role_id string) string {
	obj.mutex.Lock()
	defer obj.mutex.Unlock()
	if role_id == "" {
		c.AbortWithStatusJSON(500, gin.H{
			"message": "Username or password incorrect",
		})
		return ""
	}
	obj.Server.RoleIDNow = role_id
	return obj.Server.RoleIDNow
}
func (obj *StorageST) SaveRoleLevel(role_level string) string {
	obj.mutex.Lock()
	defer obj.mutex.Unlock()
	obj.Server.RoleLevelNow = role_level
	return obj.Server.RoleLevelNow
}

/*
tương tự như trên với username
*/
func (obj *StorageST) SaveUsername(username string) string {
	obj.mutex.Lock()
	defer obj.mutex.Unlock()
	obj.Server.Username = username
	return obj.Server.Username
}

/*
từ username mà người dùng login vào, thực hiện truy xuất data và return group id
để gán vào khi add stream
*/
func (obj *StorageST) SaveGroupID(username string) string {
	obj.mutex.Lock()
	defer obj.mutex.Unlock()
	col := client.Database("RTSP").Collection("USER")
	cur, err := col.Find(ctx, bson.M{"username": username})
	if err != nil {
		log.Fatal(err)
	}

	var results []bson.M
	if err = cur.All(ctx, &results); err != nil {
		log.Fatal(err)
	}
	if len(results) == 0 {
		return ""
	} else {
		for _, doc := range results {
			group_id := doc["group_id"].(string)
			obj.Server.GroupID = group_id
			return obj.Server.GroupID
		}
		return ""
	}
}

/*
lưu username của người dùng vào stream mà họ tạo
*/
func (obj *StorageST) UsernameForStream() string {
	obj.mutex.Lock()
	defer obj.mutex.Unlock()
	usernameforstream := obj.Server.Username
	return usernameforstream
}

func (obj *StorageST) GroupIDForStream() string {
	obj.mutex.Lock()
	defer obj.mutex.Unlock()
	groupidforstream := obj.Server.GroupID
	return groupidforstream
}

func (obj *StorageST) RoleLevelForStream() string {
	obj.mutex.Lock()
	defer obj.mutex.Unlock()
	roleidforstream := obj.Server.RoleLevelNow
	return roleidforstream
}

func (obj *StorageST) CheckOldPassword(username string, old_password string) bool {
	obj.mutex.Lock()
	defer obj.mutex.Unlock()
	col := client.Database("RTSP").Collection("USER")
	cur, err := col.Find(ctx, bson.M{"username": username})
	if err != nil {
		log.Fatal(err)
	}

	var results []bson.M
	if err = cur.All(ctx, &results); err != nil {
		log.Fatal(err)
	}
	if len(results) == 0 {
		return false
	} else {
		for _, doc := range results {
			passdata := doc["password"].(string)
			err := bcrypt.CompareHashAndPassword([]byte(passdata), []byte(old_password))
			if err == nil {
				return true
			}
		}
		return false
	}
}

/*
kiểm tra người dùng có được thực hiện quyền sửa/xóa stream, sửa role stream không
*/
func (obj *StorageST) CheckRoleEdit(role_find string, roleLevelEdit string) bool {
	obj.mutex.Lock()
	defer obj.mutex.Unlock()
	col := client.Database("RTSP").Collection("Role")
	cur, err := col.Find(ctx, bson.M{"level_role": roleLevelEdit})
	if err != nil {
		log.Fatal(err)
	}

	var results []bson.M
	if err = cur.All(ctx, &results); err != nil {
		log.Fatal(err)
	}
	if len(results) == 0 {
		return false
	} else {
		for _, doc := range results {
			id_role_edit := doc["id_role"].(string)
			return id_role_edit >= obj.Server.RoleIDNow && obj.Server.RoleIDNow <= role_find
		}
	}
	return false
}
func (obj *StorageST) CheckRoleDeleteOrInfo(role_id_find string) bool {
	obj.mutex.Lock()
	defer obj.mutex.Unlock()
	return obj.Server.RoleIDNow <= role_id_find
}

/*
kiểm tra user có phải là superuser không
*/
func (obj *StorageST) CheckRoleInfo() bool {
	obj.mutex.Lock()
	defer obj.mutex.Unlock()
	return obj.Server.RoleIDNow == "0"
}

/*
kiểm tra username khi người dùng chỉnh sửa/xóa có tồn tại hay không
*/
func CheckUsernameofEdit(username string, payload *User) bool {
	col := client.Database("RTSP").Collection("USER")
	cur, err := col.Find(ctx, bson.M{"username": username})
	if err != nil {
		log.Fatal(err)
	}

	var results []bson.M
	if err = cur.All(ctx, &results); err != nil {
		log.Fatal(err)
	}
	if len(results) == 0 {
		return false
	} else {
		if payload.RoleLevel == "" {
			for _, doc := range results {
				if roleLevel, ok := doc["role_level"].(string); ok {
					payload.RoleLevel = roleLevel
				}
			}
		}
		if payload.GroupID == "" {
			for _, doc := range results {
				if group_id, ok := doc["group_id"].(string); ok {
					payload.GroupID = group_id
				}
			}
		}
		if payload.Password == "" {
			for _, doc := range results {
				if password, ok := doc["password"].(string); ok {
					payload.Password = password
				}
			}
		}
		return true
	}
}
func CheckUsernameofFind(username string) bool {
	col := client.Database("RTSP").Collection("USER")
	cur, err := col.Find(ctx, bson.M{"username": username})
	if err != nil {
		log.Fatal(err)
	}

	var results []bson.M
	if err = cur.All(ctx, &results); err != nil {
		log.Fatal(err)
	}
	if len(results) == 0 {
		return false
	} else {
		return true
	}
}

/*
kiểm tra UUID mà superuser dùng để sửa/xóa có tồn tại hay không, return role id
*/
func CheckUUIDofFind(uuid string) string {
	col := client.Database("RTSP").Collection("StreamOfUser")
	cur, err := col.Find(ctx, bson.M{"uuid": uuid})
	if err != nil {
		log.Fatal(err)
	}

	var results []bson.M
	if err = cur.All(ctx, &results); err != nil {
		log.Fatal(err)
	}
	if len(results) == 0 {
		return ""
	} else {
		for _, doc := range results {
			role_level := doc["role_level"].(string)
			return role_level
		}
		return ""
	}
}
func CheckUUIDForEditOrDelete(uuid string) string {
	col := client.Database("RTSP").Collection("StreamOfUser")
	cur, err := col.Find(ctx, bson.M{"uuid": uuid})
	if err != nil {
		log.Fatal(err)
	}

	var results []bson.M
	if err = cur.All(ctx, &results); err != nil {
		log.Fatal(err)
	}
	if len(results) == 0 {
		return ""
	} else {
		for _, doc := range results {
			role_level := doc["role_level"].(string)
			col := client.Database("RTSP").Collection("Role")
			cur, err := col.Find(ctx, bson.M{"level_role": role_level})
			if err != nil {
				log.Fatal(err)
			}
			var role_id []bson.M
			if err = cur.All(ctx, &role_id); err != nil {
				log.Fatal(err)
			}
			if len(role_id) == 0 {
				return ""
			} else {
				for _, doc := range role_id {
					id_role := doc["id_role"].(string)
					return id_role
				}
				return ""
			}
		}
		return ""
	}
}
func CheckGroupIDForEditOrDelete(uuid string) string {
	col := client.Database("RTSP").Collection("StreamOfUser")
	cur, err := col.Find(ctx, bson.M{"uuid": uuid})
	if err != nil {
		log.Fatal(err)
	}

	var results []bson.M
	if err = cur.All(ctx, &results); err != nil {
		log.Fatal(err)
	}
	if len(results) == 0 {
		return ""
	} else {
		for _, doc := range results {
			group_id := doc["group_id"].(string)
			return group_id
		}
		return ""
	}
}

/*
kiểm tra username và uuid khi user edit stream có khớp nhau hay không
*/
func CheckUUIDofStreamForUser(uuid string) string {
	col := client.Database("RTSP").Collection("StreamOfUser")
	cur, err := col.Find(ctx, bson.M{"uuid": uuid})
	if err != nil {
		log.Fatal(err)
	}

	var results []bson.M
	if err = cur.All(ctx, &results); err != nil {
		log.Fatal(err)
	}
	if len(results) == 0 {
		return ""
	} else {
		for _, doc := range results {
			username := doc["username"].(string)
			return username
		}
		return ""
	}
}
func CheckUsernameDelete(username string) string {
	col := client.Database("RTSP").Collection("USER")
	cur, err := col.Find(ctx, bson.M{"username": username})
	if err != nil {
		log.Fatal(err)
	}
	var results []bson.M
	if err = cur.All(ctx, &results); err != nil {
		log.Fatal(err)
	}
	if len(results) == 0 {
		return ""
	} else {
		for _, doc := range results {
			role_level := doc["role_level"].(string)
			return role_level
		}
		return ""
	}
}

/*
kiểm tra xem tên đăng nhập ở phần login có tồn tại hay không, return role level
*/
func CheckUsernameLoggin(username string, password string) string {
	col := client.Database("RTSP").Collection("USER")
	cur, err := col.Find(ctx, bson.M{"username": username})
	if err != nil {
		log.Fatal(err)
	}

	var results []bson.M
	if err = cur.All(ctx, &results); err != nil {
		log.Fatal(err)
	}
	if len(results) == 0 {
		return ""
	} else {
		for _, result := range results {
			passdata, _ := result["password"].(string)
			err := bcrypt.CompareHashAndPassword([]byte(passdata), []byte(password))
			if err == nil {
				for _, doc := range results {
					role_level := doc["role_level"].(string)
					return role_level
				}
			} else {
				return ""
			}
		}
		return ""
	}
}
func CheckGroupIDEXIST(id_group string) bool {
	col := client.Database("RTSP").Collection("Group")
	cur, err := col.Find(ctx, bson.M{"id_group": id_group})
	if err != nil {
		log.Fatal(err)
	}

	var results []bson.M
	if err = cur.All(ctx, &results); err != nil {
		log.Fatal(err)
	}
	if len(results) == 0 {
		return false
	} else {
		return true
	}
}
func CheckRoleLevelEXIST(level_role string) bool {
	col := client.Database("RTSP").Collection("Role")
	cur, err := col.Find(ctx, bson.M{"level_role": level_role})
	if err != nil {
		log.Fatal(err)
	}

	var results []bson.M
	if err = cur.All(ctx, &results); err != nil {
		log.Fatal(err)
	}
	if len(results) == 0 {
		return false
	} else {
		return true
	}
}
func CheckRoleIDEXIST(id_role string) bool {
	col := client.Database("RTSP").Collection("Role")
	cur, err := col.Find(ctx, bson.M{"id_role": id_role})
	if err != nil {
		log.Fatal(err)
	}

	var results []bson.M
	if err = cur.All(ctx, &results); err != nil {
		log.Fatal(err)
	}
	if len(results) == 0 {
		return false
	} else {
		return true
	}
}

/*
kiểm tra username đã có hay chưa
*/
func CheckUsernameEXIST(username string) bool {
	col := client.Database("RTSP").Collection("USER")
	cur, err := col.Find(ctx, bson.M{"username": username})
	if err != nil {
		log.Fatal(err)
	}

	var results []bson.M
	if err = cur.All(ctx, &results); err != nil {
		log.Fatal(err)
	}
	if len(results) == 0 {
		return false
	} else {
		return true
	}
}
func (obj *StorageST) MarshalledStreamsList() (interface{}, error) {
	obj.mutex.RLock()
	defer obj.mutex.RUnlock()
	//sheriff là gì
	val, err := sheriff.Marshal(&sheriff.Options{
		Groups: []string{"api"},
	}, obj.Streams)
	if err != nil {
		return nil, err
	}
	return val, nil
}

// StreamAdd add stream
func (obj *StorageST) StreamAdd(uuid string, val StreamST) error {
	obj.mutex.Lock()
	defer obj.mutex.Unlock()
	//TODO create empty map bug save https://github.com/liip/sheriff empty not nil map[] != {} json

	//data, err := sheriff.Marshal(&sheriff.Options{
	//		Groups:     []string{"config"},
	//		ApiVersion: v2,
	//	}, obj)
	//Not Work map[] != {}
	if obj.Streams == nil {
		obj.Streams = make(map[string]StreamST)
	}
	if _, ok := obj.Streams[uuid]; ok {
		return ErrorStreamAlreadyExists
	}
	//đoạn này không hiểu gì hết
	for i, i2 := range val.Channels {
		i2 = obj.StreamChannelMake(i2)
		if !i2.OnDemand {
			i2.runLock = true
			val.Channels[i] = i2
			go StreamServerRunStreamDo(uuid, i)
		} else {
			val.Channels[i] = i2
		}
	}
	obj.Streams[uuid] = val
	err := obj.SaveConfig()
	if err != nil {
		return err
	}
	return nil
}

// StreamEdit edit stream
func (obj *StorageST) StreamEdit(uuid string, val StreamST) error {
	obj.mutex.Lock()
	defer obj.mutex.Unlock()
	if tmp, ok := obj.Streams[uuid]; ok {
		for i, i2 := range tmp.Channels {
			if i2.runLock {
				tmp.Channels[i] = i2
				obj.Streams[uuid] = tmp
				i2.signals <- SignalStreamStop
			}
		}
		for i3, i4 := range val.Channels {
			i4 = obj.StreamChannelMake(i4)
			if !i4.OnDemand {
				i4.runLock = true
				val.Channels[i3] = i4
				go StreamServerRunStreamDo(uuid, i3)
			} else {
				val.Channels[i3] = i4
			}
		}
		obj.Streams[uuid] = val
		err := obj.SaveConfig()
		if err != nil {
			return err
		}
		return nil
	}
	return ErrorStreamNotFound
}

// StreamReload reload stream
func (obj *StorageST) StopAll() {
	obj.mutex.RLock()
	defer obj.mutex.RUnlock()
	if Storage.CheckToken() != "" {
		SaveExpiredToken(Storage.CheckToken(), (*Storage).Server.Username)
	}
	if Storage.CheckTokenSuper() != "" {
		SaveExpiredToken(Storage.CheckTokenSuper(), (*Storage).Server.Username)
	}
	SaveExpiredRefreshToken(FindRefreshToken((*Storage).Server.Username), (*Storage).Server.Username)
	for _, st := range obj.Streams {
		for _, i2 := range st.Channels {
			if i2.runLock {
				i2.signals <- SignalStreamStop
			}
		}
	}
	client.Disconnect(ctx)
}

// StreamReload reload stream
func (obj *StorageST) StreamReload(uuid string) error {
	obj.mutex.RLock()
	defer obj.mutex.RUnlock()
	if tmp, ok := obj.Streams[uuid]; ok {
		for _, i2 := range tmp.Channels {
			if i2.runLock {
				i2.signals <- SignalStreamRestart
			}
		}
		return nil
	}
	return ErrorStreamNotFound
}

// StreamDelete stream
func (obj *StorageST) StreamDelete(uuid string) error {
	obj.mutex.Lock()
	defer obj.mutex.Unlock()
	if tmp, ok := obj.Streams[uuid]; ok {
		for _, i2 := range tmp.Channels {
			if i2.runLock {
				i2.signals <- SignalStreamStop
			}
		}
		delete(obj.Streams, uuid)
		err := obj.SaveConfig()
		if err != nil {
			return err
		}
		return nil
	}
	return ErrorStreamNotFound
}

// StreamInfo return stream info
func (obj *StorageST) StreamInfo(uuid string) (*StreamST, error) {
	obj.mutex.RLock()
	defer obj.mutex.RUnlock()
	if tmp, ok := obj.Streams[uuid]; ok {
		return &tmp, nil
	}
	return nil, ErrorStreamNotFound
}
