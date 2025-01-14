var passwordEncrypt = {
    pubKey: "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCDEDMOzeQQEwaE2B//bfdwjuEHMq9LeiS04W779iQU1D1q/D/fPTyQDZUTpjY1wKY7q1cFzqja9SaQOgFn3Epq1kJ05Kd1XPEonnAThWPaL+R86wx0rrT5jqEDyfsbCbnxgp+EYmuoi1oVFPUVoaIaetvdkpi1smUQ4oHEYwAc1QIDAQAB",
    sign: null,
    encrypt: function () {
        if (this.sign == null) {
            this.sign = new JSEncrypt();
            this.sign.setPublicKey(this.pubKey);
        }
        var value = document.getElementById("password").value;
        if (value) {
            value = this.sign.encrypt(value);
            document.getElementById("password").value = value;
        }
    }
};