const bsv = require('babbage-bsv')
const pushdrop = require('pushdrop')
const fs = require('fs')

/**Tempo Song Protocol fields
0=<pubkey>
1=OP_CHECKSIG
2=Protocol Namespace Address (`1LQtKKK7c1TN3UcRfsp8SqGjWtzGskze36`)
3=Song Title
4=Artist(s)
5=Description
6=Duration
7=Song NanoStore UHRP URL
8=Album Artwork NanoStore UHRP URL
9=A signature from the field 0 public key over fields 2-8
Above 9=OP_DROP / OP_2DROP — Drop fields 2-8 from the stack.**/

//Not sure what this should be set to
const TSP_PROTOCOL_ADDRESS = '1LQtKKK7c1TN3UcRfsp8SqGjWtzGskze36'

class TSPTopicManager {

  async getDocumentation() {
    //Source: melvingeorge.me
    let readme = await fs.readFile('../README.md', (err, buff) => {
      if (err) {
        console.log('Unable to read file')
        return
      }
      return buff.toString()
    })
    return readme
  }

  /**
   * Returns the outputs from the TSP transaction that are admissible.
   * @param {Object} obj all params given in an object
   * @param {Object} obj.parsedTransaction transaction containing outputs to admit into the current topic
   * @returns
   */

  identifyAdmissibleOutputs({ parsedTransaction }) {
    try {
      const outputs = []

      // Validate params
      if (!Array.isArray(parsedTransaction.inputs) || parsedTransaction.inputs.length < 1) {
        const e = new Error('An array of transaction inputs is required!')
        e.code = 'ERR_TX_INPUTS_REQUIRED'
        throw e
      }
      if (!Array.isArray(parsedTransaction.outputs) || parsedTransaction.outputs.length < 1) {
        const e = new Error('Transaction outputs must be included as an array!')
        e.code = 'ERR_TX_OUTPUTS_REQUIRED'
        throw e
      }

      // Try to decode and validate transaction outputs
      for (const [i, output] of parsedTransaction.outputs.entries()) {
        // Decode the TSP account fields
        try {
          const result = pushdrop.decode({
            script: output.script.toHex(),
            fieldFormat: 'buffer'
          })

          if (result.fields[1].toString() !== TSP_PROTOCOL_ADDRESS) {
            const e = new Error('This transaction is not a valid TSP token!')
            e.code = 'ERR_UNDEFINED_OUT'
            throw e
          }

          // Use ECDSA to verify signature
          const hasValidSignature = bsv.crypto.ECDSA.verify(
            bsv.crypto.Hash.sha256(Buffer.concat(result.fields)),
            bsv.crypto.Signature.fromString(result.signature),
            bsv.PublicKey.fromString(result.lockingPublicKey)
          )
          if (!hasValidSignature) {
            const e = new Error('Invalid Signature')
            e.code = 'ERR_INVALID_SIGNATURE'
            throw e
          }
          outputs.push(i)

        } catch (error) {
          // Probably not a PushDrop token so do nothing
          console.log(error)
        }
      }
      if (outputs.length === 0) {
        const e = new Error(
          'This transaction does not publish a valid TSP Advertisement descriptor!'
        )
        e.code = 'ERR_INVALID_ADVERTISEMENT'
        throw e
      }

      // Returns an array of output numbers
      return outputs
    } catch (error) {
      return []
    }
  }
}
module.exports = TSPTopicManager
