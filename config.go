package okta

import "github.com/go-ini/ini"

type OktaConfig struct {
	*ini.File
}

type OktaTile struct {
	BaseURL   string `ini:"baseUrl"`
	AppURL    string `ini:"appUrl"`
	AWSKey    string `ini:"aws_role_lookup_key,omitempty"`
	AWSSecret string `ini:"aws_role_lookup_secret,omitempty"`
}

func ReadOktaConfig(fname string) (*OktaConfig, error) {
	cfg, err := ini.Load(fname)
	if err != nil {
		return nil, err
	}
	return &OktaConfig{cfg}, nil
}

func (cfg *OktaConfig) GetTile(name string) (*OktaTile, error) {

	tile := new(OktaTile)
	err := cfg.Section(name).MapTo(tile)
	if err != nil {
		return nil, err
	}
	return tile, nil
}

func (cfg *OktaConfig) SetTile(name string, tile *OktaTile) error {
	err := cfg.Section(name).ReflectFrom(tile)
	return err
}
