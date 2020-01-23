package com.example.server

import com.example.flow.ExampleFlow.Initiator
import com.example.state.IOUState
import net.corda.core.contracts.StateAndRef
import net.corda.core.identity.CordaX500Name
import net.corda.core.messaging.startTrackedFlow
import net.corda.core.messaging.vaultQueryBy
import net.corda.core.utilities.getOrThrow
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType.APPLICATION_JSON_VALUE
import org.springframework.http.MediaType.TEXT_PLAIN_VALUE
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.io.File
import java.nio.file.Files
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.servlet.http.HttpServletRequest


val SERVICE_NAMES = listOf("Notary", "Network Map Service")

/**
 *  A Spring Boot Server API controller for interacting with the node via RPC.
 */

@RestController
@RequestMapping("/api/example/") // The paths for GET and POST requests are relative to this base path.
class MainController(rpc: NodeRPCConnection) {

    companion object {
        private val logger = LoggerFactory.getLogger(RestController::class.java)
    }

    private val myLegalName = rpc.proxy.nodeInfo().legalIdentities.first().name
    private val proxy = rpc.proxy

    /**
     * Returns the node's name.
     */
    @GetMapping(value = [ "me" ], produces = [ APPLICATION_JSON_VALUE ])
    fun whoami() = mapOf("me" to myLegalName)

    /**
     * Returns all parties registered with the network map service. These names can be used to look up identities using
     * the identity service.
     */
    @GetMapping(value = [ "peers" ], produces = [ APPLICATION_JSON_VALUE ])
    fun getPeers(): Map<String, List<CordaX500Name>> {
        val nodeInfo = proxy.networkMapSnapshot()
        return mapOf("peers" to nodeInfo
                .map { it.legalIdentities.first().name }
                //filter out myself, notary and eventual network map started by driver
                .filter { it.organisation !in (SERVICE_NAMES + myLegalName.organisation) })
    }

    /**
     * generates new keys for signing a contract message.
     */
    @GetMapping(value = [ "generatekeys" ])
    fun generateKeys() : String {
        var gk: GenerateKeys? = null
        try {
            gk = GenerateKeys(1024)
            gk.createKeys()
            gk.writeToFile("KeyPair/publicKey", gk.getPublicKey().getEncoded());
            gk.writeToFile("KeyPair/privateKey", gk.getPrivateKey().getEncoded());
        } catch (e: Throwable) {
            System.err.println(e.message)
        } catch (e: NoSuchProviderException) {
            System.err.println(e.message)
        }
        return "Keys Generated";

        //    try {
//        Signature signature = Signature.getInstance("");
//        PublicKey publicKey1 = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKey));
//        signature.initVerify(publicKey1);
//        signature.update(signedMessage);
//        signature.verify()
//    } catch (NoSuchAlgorithmException e) {
//        e.printStackTrace();
//    } catch (InvalidKeySpecException e) {
//        e.printStackTrace();
//    } catch (InvalidKeyException e) {
//        e.printStackTrace();
//    } catch (SignatureException e) {
//        e.printStackTrace();
//    }
    }

    /**
     * Displays all IOU states that exist in the node's vault.
     */
    @GetMapping(value = [ "ious" ], produces = [ APPLICATION_JSON_VALUE ])
    fun getIOUs() : ResponseEntity<List<StateAndRef<IOUState>>> {
        println("Vesification success:"+verifySignature(
                proxy.vaultQueryBy<IOUState>().states.get(0).state.data.publicKey,
                proxy.vaultQueryBy<IOUState>().states.get(0).state.data.signedMessage
        ));
        return ResponseEntity.ok(proxy.vaultQueryBy<IOUState>().states)
    }

    fun getPublicKey(filename:String):PublicKey{
        val keyBytes: ByteArray = Files.readAllBytes(File(filename).toPath())
        val spec = X509EncodedKeySpec(keyBytes)
        val kf: KeyFactory = KeyFactory.getInstance("RSA")
        return kf.generatePublic(spec)
    }

    //Method to retrieve the Private Key from a file
    @Throws(Exception::class)
    fun getPrivate(filepath: String): PrivateKey {
        val keyBytes = Files.readAllBytes(File(filepath).toPath())
        val spec = PKCS8EncodedKeySpec(keyBytes)
        val kf = KeyFactory.getInstance("RSA")
        return kf.generatePrivate(spec)
    }
    fun signMessage(message:ByteArray,filepath:String):ByteArray{
        val rsa: Signature = Signature.getInstance("SHA1withRSA")
        rsa.initSign(getPrivate(filepath))
        rsa.update(message)
        return rsa.sign()
    }

    fun verifySignature(publicKey:ByteArray, signedData:ByteArray):Boolean{
        val signature: Signature = Signature.getInstance("SHA1withRSA")
        val publicKey:PublicKey =  KeyFactory.getInstance("RSA").generatePublic(
                X509EncodedKeySpec(
                        publicKey
                ));
        signature.initVerify(publicKey);
        signature.update("msg".toByteArray());
        return signature.verify(signedData)
    }
    /**
     * Initiates a flow to agree an IOU between two parties.
     *
     * Once the flow finishes it will have written the IOU to ledger. Both the lender and the borrower will be able to
     * see it when calling /spring/api/ious on their respective nodes.
     *
     * This end-point takes a Party name parameter as part of the path. If the serving node can't find the other party
     * in its network map cache, it will return an HTTP bad request.
     *
     * The flow is invoked asynchronously. It returns a future when the flow's call() method returns.
     */

    @PostMapping(value = [ "create-iou" ], produces = [ TEXT_PLAIN_VALUE ], headers = [ "Content-Type=application/x-www-form-urlencoded" ])
    fun createIOU(request: HttpServletRequest): ResponseEntity<String> {
        val iouValue = request.getParameter("iouValue").toInt()
        val partyName = request.getParameter("partyName")
        val publicKey:PublicKey = getPublicKey("KeyPair/publicKey");
        val signedMessage:ByteArray  = signMessage("msg".toByteArray(),"KeyPair/PrivateKey")
        if(partyName == null){
            return ResponseEntity.badRequest().body("Query parameter 'partyName' must not be null.\n")
        }
        if (iouValue <= 0 ) {
            return ResponseEntity.badRequest().body("Query parameter 'iouValue' must be non-negative.\n")
        }
        val partyX500Name = CordaX500Name.parse(partyName)
        val otherParty = proxy.wellKnownPartyFromX500Name(partyX500Name) ?: return ResponseEntity.badRequest().body("Party named $partyName cannot be found.\n")

        return try {
            val signedTx = proxy.startTrackedFlow(::Initiator, iouValue, otherParty,publicKey.encoded,signedMessage).returnValue.getOrThrow()
            ResponseEntity.status(HttpStatus.CREATED).body("Transaction id ${signedTx.id} committed to ledger.\n")

        } catch (ex: Throwable) {
            logger.error(ex.message, ex)
            ResponseEntity.badRequest().body(ex.message!!)
        }
    }

    /**
     * Displays all IOU states that only this node has been involved in.
     */
    @GetMapping(value = [ "my-ious" ], produces = [ APPLICATION_JSON_VALUE ])
    fun getMyIOUs(): ResponseEntity<List<StateAndRef<IOUState>>>  {
        val myious = proxy.vaultQueryBy<IOUState>().states.filter { it.state.data.lender.equals(proxy.nodeInfo().legalIdentities.first()) }
        return ResponseEntity.ok(myious)
    }

}
