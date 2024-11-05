package main

import (
	"github.com/blankbro/wecom-app-svr"
	"gopkg.in/yaml.v3"
	"log"
	"os"
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

func main() {
	// 读取配置文件
	bytes, err := os.ReadFile("examples/config.yaml")
	if err != nil {
		log.Printf("读取配置文件失败: %v\n", err)
		return
	}

	config := Config{}
	err = yaml.Unmarshal(bytes, &config)
	if err != nil {
		log.Println("解析 yaml 文件失败：", err)
		return
	}

	log.Printf("config server → %+v\n", config.Server)
	log.Printf("config wecom → %+v\n", config.Wecom)

	wecom_app_svr.Run(
		config.Server.Port, config.Wecom.Path,
		config.Wecom.Token, config.Wecom.AesKey, config.Wecom.CorpId,
		func(msgContent wecom_app_svr.MsgContent) {
			// 编写自己的逻辑
		},
	)
}
