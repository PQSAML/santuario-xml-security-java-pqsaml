/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.xml.security.algorithms.implementations;

import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.algorithms.SignatureAlgorithmSpi;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public abstract class SignatureBaseComposite extends SignatureAlgorithmSpi {
    private static final Logger LOG = System.getLogger(SignatureBaseComposite.class.getName());

    /** Field algorithm */
    private final Signature signatureAlgorithm;

    /**
     * Constructor SignatureBaseComposite
     *
     * @throws XMLSignatureException
     */
    public SignatureBaseComposite() throws XMLSignatureException {
        this(null);
    }

    public SignatureBaseComposite(Provider provider) throws XMLSignatureException {
        String algorithmID = JCEMapper.translateURItoJCEID(this.engineGetURI());
        LOG.log(Level.DEBUG, "Created SignatureComposite using {}", algorithmID);

        try {
            if (provider == null) {
                String providerId = JCEMapper.getProviderId();
                if (providerId == null) {
                    this.signatureAlgorithm = Signature.getInstance(algorithmID);

                } else {
                    this.signatureAlgorithm = Signature.getInstance(algorithmID, providerId);
                }

            } else {
                this.signatureAlgorithm = Signature.getInstance(algorithmID, provider);
            }

        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            Object[] exArgs = {algorithmID, ex.getLocalizedMessage()};
            throw new XMLSignatureException("algorithms.NoSuchAlgorithm", exArgs);
        }
    }

    /** {@inheritDoc} */
    protected void engineSetParameter(AlgorithmParameterSpec params)
            throws XMLSignatureException {
        try {
            this.signatureAlgorithm.setParameter(params);
        } catch (InvalidAlgorithmParameterException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /** {@inheritDoc} */
    protected boolean engineVerify(byte[] signature) throws XMLSignatureException {
        try {
            return this.signatureAlgorithm.verify(signature);
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /** {@inheritDoc} */
    protected void engineInitVerify(Key publicKey) throws XMLSignatureException {
        engineInitVerify(publicKey, this.signatureAlgorithm);
    }

    /** {@inheritDoc} */
    protected byte[] engineSign() throws XMLSignatureException {
        try {
            return this.signatureAlgorithm.sign();
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /** {@inheritDoc} */
    protected void engineInitSign(Key privateKey, SecureRandom secureRandom)
            throws XMLSignatureException {
        engineInitSign(privateKey, secureRandom, this.signatureAlgorithm);
    }

    /** {@inheritDoc} */
    protected void engineInitSign(Key privateKey) throws XMLSignatureException {
        engineInitSign(privateKey, (SecureRandom)null);
    }

    /** {@inheritDoc} */
    protected void engineUpdate(byte[] input) throws XMLSignatureException {
        try {
            this.signatureAlgorithm.update(input);
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /** {@inheritDoc} */
    protected void engineUpdate(byte input) throws XMLSignatureException {
        try {
            this.signatureAlgorithm.update(input);
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /** {@inheritDoc} */
    protected void engineUpdate(byte[] buf, int offset, int len) throws XMLSignatureException {
        try {
            this.signatureAlgorithm.update(buf, offset, len);
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /** {@inheritDoc} */
    protected String engineGetJCEAlgorithmString() {
        return this.signatureAlgorithm.getAlgorithm();
    }

    /** {@inheritDoc} */
    protected String engineGetJCEProviderName() {
        return this.signatureAlgorithm.getProvider().getName();
    }

    /** {@inheritDoc} */
    protected void engineSetHMACOutputLength(int HMACOutputLength)
            throws XMLSignatureException {
        throw new XMLSignatureException("algorithms.HMACOutputLengthOnlyForHMAC");
    }

    /** {@inheritDoc} */
    protected void engineInitSign(
            Key signingKey, AlgorithmParameterSpec algorithmParameterSpec
    ) throws XMLSignatureException {
        throw new XMLSignatureException("algorithms.CannotUseAlgorithmParameterSpecOnSignatureBaseComposite");
    }

    public static class SignatureMLDSA44andECDSAP256 extends SignatureBaseComposite
    {
        /**
         * Constructor MLDSA44andECDSAP256
         *
         * @throws XMLSignatureException
         */
        public SignatureMLDSA44andECDSAP256() throws XMLSignatureException {
            super();
        }

        public SignatureMLDSA44andECDSAP256(Provider provider) throws XMLSignatureException {
            super(provider);
        }

        /** {@inheritDoc} */
        @Override
        public String engineGetURI() {
            return XMLSignature.ALGO_ID_SIGNATURE_MLDSA44andECDSAP256;
        }
    }

    public static class SignatureMLDSA87andECDSAP384 extends SignatureBaseComposite
    {
        /**
         * Constructor MLDSA87andECDSAP384
         *
         * @throws XMLSignatureException
         */
        public SignatureMLDSA87andECDSAP384() throws XMLSignatureException {
            super();
        }

        public SignatureMLDSA87andECDSAP384(Provider provider) throws XMLSignatureException {
            super(provider);
        }

        /** {@inheritDoc} */
        @Override
        public String engineGetURI() {
            return XMLSignature.ALGO_ID_SIGNATURE_MLDSA87andECDSAP384;
        }
    }

    public static class SignatureMLDSA87andECDSAP521 extends SignatureBaseComposite
    {
        /**
         * Constructor MLDSA87andECDSAP521
         *
         * @throws XMLSignatureException
         */
        public SignatureMLDSA87andECDSAP521() throws XMLSignatureException {
            super();
        }

        public SignatureMLDSA87andECDSAP521(Provider provider) throws XMLSignatureException {
            super(provider);
        }

        /** {@inheritDoc} */
        @Override
        public String engineGetURI() {
            return XMLSignature.ALGO_ID_SIGNATURE_MLDSA87andECDSAP521;
        }
    }

    public static class SignatureFalcon512andECDSAP256 extends SignatureBaseComposite
    {
        /**
         * Constructor Falcon512andECDSAP256
         *
         * @throws XMLSignatureException
         */
        public SignatureFalcon512andECDSAP256() throws XMLSignatureException {
            super();
        }

        public SignatureFalcon512andECDSAP256(Provider provider) throws XMLSignatureException {
            super(provider);
        }

        /** {@inheritDoc} */
        @Override
        public String engineGetURI() {
            return XMLSignature.ALGO_ID_SIGNATURE_Falcon512andECDSAP256;
        }
    }

    public static class SignatureFalcon1024andECDSAP521 extends SignatureBaseComposite
    {
        /**
         * Constructor Falcon1024andECDSAP521
         *
         * @throws XMLSignatureException
         */
        public SignatureFalcon1024andECDSAP521() throws XMLSignatureException {
            super();
        }

        public SignatureFalcon1024andECDSAP521(Provider provider) throws XMLSignatureException {
            super(provider);
        }

        /** {@inheritDoc} */
        @Override
        public String engineGetURI() {
            return XMLSignature.ALGO_ID_SIGNATURE_Falcon1024andECDSAP521;
        }
    }
}