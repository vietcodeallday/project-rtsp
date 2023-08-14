package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-redis/redis"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var client *mongo.Client
var ctx context.Context
var rdb *redis.Client

func init() {
	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	clientOptions := options.Client().ApplyURI("mongodb+srv://quocvietvu81:quocvietvu81@intern.ye7jfrl.mongodb.net/RTSP?retryWrites=true&w=majority").SetServerAPIOptions(serverAPI)
	// clientOptions := options.Client().ApplyURI("mongodb://192.168.56.1:27017")
	client, _ = mongo.Connect(context.TODO(), clientOptions)
	ctx, _ = context.WithTimeout(context.Background(), 90*time.Hour)
	CreateIndexUSER()
	CreateIndexStream()
	CreateIndexRole()
	CreateIndexGroup()
	CreateIndexBlackList()

	options := &redis.Options{
		Addr:     "redis-18352.c292.ap-southeast-1-1.ec2.cloud.redislabs.com:18352",
		Password: "MESkRZKAbkzJg3wlL3uqWAmDojXR5qBA",
		DB:       0,
	}
	rdb = redis.NewClient(options)

	addSuperUser()
	AddRoleSuperUser()
}
func main() {
	log.WithFields(logrus.Fields{
		"module": "main",
		"func":   "main",
	}).Info("Server CORE start")
	go HTTPAPIServer()
	go RTSPServer()
	go Storage.StreamChannelRunAll()
	signalChanel := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(signalChanel, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-signalChanel
		log.WithFields(logrus.Fields{
			"module": "main",
			"func":   "main",
		}).Info("Server receive signal", sig)
		done <- true
	}()
	log.WithFields(logrus.Fields{
		"module": "main",
		"func":   "main",
	}).Info("Server start success a wait signals")
	<-done
	Storage.StopAll()
	time.Sleep(2 * time.Second)
	log.WithFields(logrus.Fields{
		"module": "main",
		"func":   "main",
	}).Info("Server stop working by signal")
}
