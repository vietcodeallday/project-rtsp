package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var client *mongo.Client
var ctx context.Context

func init() {
	clientOptions := options.Client().ApplyURI("mongodb://192.168.56.1:27017")
	client, _ = mongo.Connect(context.TODO(), clientOptions)
	ctx, _ = context.WithTimeout(context.Background(), 240*time.Hour)
}
func main() {
	defer client.Disconnect(ctx)
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
