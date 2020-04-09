package seal

import (
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-kms-wrapping/wrappers/yandexcloudkms"
	"github.com/hashicorp/vault/command/server"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/vault"
	"github.com/hashicorp/vault/vault/seal"
)

func configureYandexCloudKMSSeal(configSeal *server.Seal, infoKeys *[]string, info *map[string]string, logger hclog.Logger, inseal vault.Seal) (vault.Seal, error) {
	kms := yandexcloudkms.NewWrapper(nil)
	kmsInfo, err := kms.SetConfig(configSeal.Config)
	if err != nil {
		// If the error is any other than logical.KeyNotFoundError, return the error
		if !errwrap.ContainsType(err, new(logical.KeyNotFoundError)) {
			return nil, err
		}
	}
	autoseal := vault.NewAutoSeal(&seal.Access{
		Wrapper: kms,
	})
	if kmsInfo != nil {
		*infoKeys = append(*infoKeys, "Seal Type", "Yandex.Cloud KeyID")
		(*info)["Seal Type"] = configSeal.Type
		(*info)["Yandex.Cloud KeyID"] = kmsInfo["kms_key_id"]
	}
	return autoseal, nil
}
