import { KMS, SignCommandInput } from '@aws-sdk/client-kms';

export type SignParams = {
  keyId: SignCommandInput['KeyId']
  message: string
  kmsInstance: KMS
}

export type GetEthAddressFromKMSparams = {
  keyId: SignCommandInput['KeyId']
  kmsInstance: KMS
}

export type GetPublicKeyParams = {
  keyId: SignCommandInput['KeyId']
  kmsInstance: KMS
}

export type CreateSignatureParams = SignParams & {
  address: string
}
