package main

import (
	"fmt"
	nested "github.com/antonfisher/nested-logrus-formatter"
	"github.com/blankbro/wecom-app-svr"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	"os"
	"runtime"
	"time"
)

type Config struct {
	Server Server
	Wecom  WeCom
}

type Server struct {
	Port string
}

type WeCom struct {
	Token  string
	AesKey string `yaml:"aes_key"`
	CorpId string `yaml:"corp_id"`
	Path   string
}

func init() {
	// Trace > Debug > Info > Warn > Error > Fatal > Panic
	logrus.SetLevel(logrus.InfoLevel)
	// 打印源文件
	logrus.SetReportCaller(true)
	// 指定源文件格式
	logrus.SetFormatter(&nested.Formatter{
		HideKeys:        true,
		TimestampFormat: time.DateTime,
		CallerFirst:     true,
		CustomCallerFormatter: func(frame *runtime.Frame) string {
			return fmt.Sprintf(" %s:%d", frame.File, frame.Line)
		},
	})
}

func main() {
	// 读取配置文件
	bytes, err := os.ReadFile("examples/config.yml")
	if err != nil {
		logrus.Fatalf("读取配置文件失败: %v", err)
	}

	config := Config{}
	err = yaml.Unmarshal(bytes, &config)
	if err != nil {
		logrus.Fatalf("解析 yaml 文件失败: %v", err)
	}

	logrus.Infof("config server → %+v", config.Server)
	logrus.Infof("config wecom → %+v", config.Wecom)

	wecom_app_svr.Run(
		config.Server.Port, config.Wecom.Path,
		config.Wecom.Token, config.Wecom.AesKey, config.Wecom.CorpId,
		func(msgContent wecom_app_svr.MsgContent) {
			// 编写自己的逻辑
		},
	)
}
