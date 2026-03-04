#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Apigee Python Callout - RSA-SHA256 Signature Generation
Compatible with Apigee's Python runtime
"""

import json
import base64
import sys

# Apigee uses Jython, need to import Java classes for RSA
from java.security import KeyFactory, Signature
from java.security.spec import PKCS8EncodedKeySpec
from java.nio.charset import StandardCharsets
from java.util import Base64 as JavaBase64


def execute(message_context, execution_context):
    """
    Main entry point for Apigee Python callout
    Uses Java crypto libraries via Jython
    """
    try:
        # Get configuration from flow variables
        client_secret = str(message_context.getVariable("signature.client.secret") or "")
        private_key_pem = str(message_context.getVariable("signature.private.key") or "")
        
        # Get request details
        method = str(message_context.getVariable("request.verb") or "POST")
        request_body = str(message_context.getVariable("request.content") or "")
        query_string = str(message_context.getVariable("request.querystring") or "")
        
        print "=== RSA Signature Generation ==="
        
        # Extract values from request body
        path_value = ""
        time_stamp = ""
        body = ""
        
        if method != "GET" and request_body:
            try:
                body_json = json.loads(request_body)
                
                # Extract from header
                if "header" in body_json:
                    path_value = body_json["header"].get("pathValue", "")
                    time_stamp = body_json["header"].get("transctionDateTime", "")
                
                # Re-serialize body
                body = json.dumps(body_json, separators=(',', ':'))
                
            except Exception as e:
                print "Error parsing JSON: " + str(e)
                path_value = str(message_context.getVariable("proxy.pathsuffix") or "")
        
        # Fallback for path if not in body
        if not path_value:
            path_value = str(message_context.getVariable("proxy.pathsuffix") or "")
        
        # Construct dataToSign
        data_to_sign = client_secret + "," + time_stamp + "," + path_value + "," + query_string + "," + body
        
        print "Path: " + path_value
        print "Timestamp: " + time_stamp
        print "DataToSign length: " + str(len(data_to_sign))
        
        # Clean the private key
        cleaned_pem = private_key_pem.replace("-----BEGIN PRIVATE KEY-----", "")
        cleaned_pem = cleaned_pem.replace("-----END PRIVATE KEY-----", "")
        cleaned_pem = cleaned_pem.replace("\n", "").replace("\r", "").replace(" ", "")
        
        # Decode the private key
        decoder = JavaBase64.getDecoder()
        key_bytes = decoder.decode(cleaned_pem)
        
        # Load private key
        key_spec = PKCS8EncodedKeySpec(key_bytes)
        key_factory = KeyFactory.getInstance("RSA")
        private_key = key_factory.generatePrivate(key_spec)
        
        # Create signature
        signer = Signature.getInstance("SHA256withRSA")
        signer.initSign(private_key)
        signer.update(data_to_sign.encode('utf-8'))
        signature_bytes = signer.sign()
        
        # Base64 encode
        encoder = JavaBase64.getEncoder()
        signature = encoder.encodeToString(signature_bytes)
        
        print "Signature generated successfully"
        
        # Set variables
        message_context.setVariable("signature.value", signature)
        message_context.setVariable("signature.success", "true")
        message_context.setVariable("request.header.x-bab-signature", signature)
        
        return "SUCCESS"
        
    except Exception as e:
        error_msg = str(e)
        print "ERROR: " + error_msg
        message_context.setVariable("signature.error", error_msg)
        message_context.setVariable("signature.success", "false")
        return "ABORT"
