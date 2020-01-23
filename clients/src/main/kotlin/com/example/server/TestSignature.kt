package com.example.server

import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

fun main(args: Array<String>) {
    val signature: Signature = Signature.getInstance("SHA1withRSA")
    val publicKey: PublicKey =  KeyFactory.getInstance("RSA").generatePublic(
            X509EncodedKeySpec(
                    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCXW4L4MBVLbuD34QwBOOOOfzbPRLpXhTQPyoXopwx1352Eouoen7nUUJmbLlRvlrFzjoZjCl9Og4R1qhZWLvv8yUvgIZ2XT+YhWI9WmsZDRXA0yNSt+Rgkhe0g4EOwsT1a/HfJ4foAsPQNu5zntKbMxm9M1nhCPhbgf+yEgBHk9QIDAQAB".toByteArray()
            ));
    signature.initVerify(publicKey);
    signature.update("msg".toByteArray());
    println(signature.verify("QN+QdbLL5icdgL8vgC8B6mo2FxJ1aP4VBFRze1IhqA0dapYtUHSHk/LnS685rEWvHvKqyJFcuxUIYjPpjowYl1H4yDlmbCOunP5M/8OlSVIVEir6kmI2XQbRaazK/zGngrNhJHCfLOdB7FfNuR9/2aeclf8NOWWeD8o8/4DxL14=".toByteArray()))
}