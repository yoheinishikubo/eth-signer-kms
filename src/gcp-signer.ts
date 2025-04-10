import { utils, Signer, providers, BigNumber } from 'ethers'
import { keccak256 } from '@ethersproject/keccak256'
import { _TypedDataEncoder } from '@ethersproject/hash'
import {
  getPublicKey,
  getEthereumAddress,
  requestKmsSignature,
  determineCorrectV
} from 'ethers-gcp-kms-signer/dist/util/gcp-kms-utils'

import {
  TypedDataDomain,
  TypedDataField,
  TypedDataSigner
} from '@ethersproject/abstract-signer'

export interface GcpKmsSignerCredentials {
  projectId: string
  locationId: string
  keyRingId: string
  keyId: string
  keyVersion: string
}

export class GCPSigner extends Signer implements TypedDataSigner {
  private kmsCredentials: GcpKmsSignerCredentials
  private address: string

  constructor(
    public provider: providers.Provider,
    kmsCredentials: GcpKmsSignerCredentials
  ) {
    super()
    this.kmsCredentials = kmsCredentials
  }

  async getAddress(): Promise<string> {
    if (!this.address) {
      const publicKey = await getPublicKey(this.kmsCredentials)
      this.address = await getEthereumAddress(publicKey)
    }
    return this.address
  }

  async _signDigest(digestString: string): Promise<string> {
    const digestBuffer = Buffer.from(utils.arrayify(digestString))
    const sig = await requestKmsSignature(digestBuffer, this.kmsCredentials)
    const ethAddr = await this.getAddress()
    const { v } = determineCorrectV(digestBuffer, sig.r, sig.s, ethAddr)
    return utils.joinSignature({
      v,
      r: `0x${sig.r.toString('hex')}`,
      s: `0x${sig.s.toString('hex')}`
    })
  }

  async signMessage(message: utils.Bytes | string): Promise<string> {
    return this._signDigest(utils.hashMessage(message))
  }

  async _signTypedData(
    domain: TypedDataDomain,
    types: Record<string, Array<TypedDataField>>,
    value: Record<string, any>
  ): Promise<string> {
    const hash = _TypedDataEncoder.hash(domain, types, value)
    return this._signDigest(hash)
  }

  async signTypedData(
    domain: TypedDataDomain,
    types: Record<string, Array<TypedDataField>>,
    value: Record<string, any>
  ): Promise<string> {
    const hash = _TypedDataEncoder.hash(domain, types, value)
    return this._signDigest(hash)
  }


  async signTransaction(
    transaction: providers.TransactionRequest
  ): Promise<string> {
    const tx = await utils.resolveProperties(transaction)
    const baseTx: utils.UnsignedTransaction = {
      chainId: tx.chainId || undefined,
      data: tx.data || undefined,
      gasLimit: tx.gasLimit || undefined,
      gasPrice: tx.gasPrice || undefined,
      nonce: tx.nonce ? BigNumber.from(tx.nonce).toNumber() : undefined,
      to: tx.to || undefined,
      value: tx.value || undefined,
      type: tx.type,
      maxFeePerGas: tx.maxFeePerGas || undefined,
      maxPriorityFeePerGas: tx.maxPriorityFeePerGas || undefined
    }

    if (baseTx.type === 0) {
      delete baseTx.maxFeePerGas
      delete baseTx.maxPriorityFeePerGas
    }

    const unsignedTx = utils.serializeTransaction(baseTx)
    const hash = keccak256(utils.arrayify(unsignedTx))

    const sig = await this._signDigest(hash)

    const result = utils.serializeTransaction(baseTx, sig)
    return result
  }

  connect(provider: providers.Provider): Signer {
    return new GCPSigner(provider, this.kmsCredentials)
  }
}
