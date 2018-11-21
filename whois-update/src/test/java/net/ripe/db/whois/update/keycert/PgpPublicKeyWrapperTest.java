package net.ripe.db.whois.update.keycert;

import com.google.common.collect.Lists;
import net.ripe.db.whois.common.DateTimeProvider;
import net.ripe.db.whois.common.rpsl.RpslObject;
import org.apache.commons.io.Charsets;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyFlags;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.bc.BcPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.joda.time.LocalDateTime;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.core.io.ClassPathResource;

import javax.annotation.Nullable;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Provider;
import java.util.Iterator;
import java.util.List;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class PgpPublicKeyWrapperTest {

    private static final Provider PROVIDER = new BouncyCastleProvider();

    @Mock DateTimeProvider dateTimeProvider;

    private RpslObject pgpKeycert;
    private RpslObject anotherPgpKeycert;
    private RpslObject x509Keycert;

    @Before
    public void setup() throws Exception {
        when(dateTimeProvider.getCurrentDateTime()).thenReturn(LocalDateTime.now());
        pgpKeycert = RpslObject.parse(getResource("keycerts/PGPKEY-A8D16B70.TXT"));
        anotherPgpKeycert = RpslObject.parse(getResource("keycerts/PGPKEY-28F6CD6C.TXT"));
        x509Keycert = RpslObject.parse(getResource("keycerts/X509-1.TXT"));
    }

    @Test
    public void pgpFingerprint() throws Exception {
        PgpPublicKeyWrapper subject = PgpPublicKeyWrapper.parse(pgpKeycert);

        assertThat(subject.getFingerprint(),
                is("D079 99F1 92D5 41B6 E7BC  6578 9175 DB8D A8D1 6B70"));
    }

    @Test
    public void isPgpKey() throws IOException {
        assertThat(PgpPublicKeyWrapper.looksLikePgpKey(pgpKeycert), is(true));
        assertThat(PgpPublicKeyWrapper.looksLikePgpKey(x509Keycert), is(false));
    }

    @Test
    public void isEquals() throws IOException {
        PgpPublicKeyWrapper subject = PgpPublicKeyWrapper.parse(pgpKeycert);
        PgpPublicKeyWrapper another = PgpPublicKeyWrapper.parse(anotherPgpKeycert);

        assertThat(subject.equals(subject), is(true));
        assertThat(subject.equals(another), is(false));
    }

    @Test
    public void method() {
        PgpPublicKeyWrapper subject = PgpPublicKeyWrapper.parse(pgpKeycert);

        assertThat(subject.getMethod(), is("PGP"));
    }

    @Test
    public void owner() {
        PgpPublicKeyWrapper subject = PgpPublicKeyWrapper.parse(pgpKeycert);

        assertThat(subject.getOwners(), containsInAnyOrder("Test Person5 <noreply5@ripe.net>"));
    }

    @Test
    public void multiplePublicKeys() throws Exception {
        try {
            PgpPublicKeyWrapper.parse(RpslObject.parse(getResource("keycerts/PGPKEY-MULTIPLE-PUBLIC-KEYS.TXT")));
            fail();
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage(), is("The supplied object has multiple keys"));
        }
    }

    @Test
    public void onePublicKeyWithMultipleSubkeys() throws Exception {
        PgpPublicKeyWrapper result = PgpPublicKeyWrapper.parse(RpslObject.parse(getResource("keycerts/PGPKEY-MULTIPLE-SUBKEYS.TXT")));

        assertNotNull(result.getPublicKey());
        assertThat(result.getSubKeys(), hasSize(1));
    }

    @Test
    public void parsePrivateKey() throws Exception {
        try {
            PgpPublicKeyWrapper.parse(RpslObject.parse(getResource("keycerts/PGPKEY-PRIVATE-KEY.TXT")));
            fail();
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage(), is("The supplied object has no key"));
        }
    }

    @Test
    public void isExpired() throws Exception {
        PgpPublicKeyWrapper subject = PgpPublicKeyWrapper.parse(
                RpslObject.parse(
                        "key-cert:       PGPKEY-C88CA438\n" +
                        "method:         PGP\n" +
                        "owner:          Expired <expired@ripe.net>\n" +
                        "fingerpr:       610A 2457 2BA3 A575 5F85  4DD8 5E62 6C72 C88C A438\n" +
                        "certif:         -----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                        "certif:         Version: GnuPG v1.4.12 (Darwin)\n" +
                        "certif:         Comment: GPGTools - http://gpgtools.org\n" +
                        "certif:\n" +
                        "certif:         mI0EUOoKSgEEAMvJBJzUBKDA8BGK+KpJMuGSOXnQgvymxgyOUOBVkLpeOcPQMy1A\n" +
                        "certif:         4fffXJ4V0xdlqtikDATCnSIBS17ihi7xD8fUvKF4dJrq+rmaVULoy06B68IcfYKQ\n" +
                        "certif:         yoRJqGii/1Z47FuudeJp1axQs1JER3OJ64IHuLblFIT7oS+YWBLopc1JABEBAAG0\n" +
                        "certif:         GkV4cGlyZWQgPGV4cGlyZWRAcmlwZS5uZXQ+iL4EEwECACgFAlDqCkoCGwMFCQAB\n" +
                        "certif:         UYAGCwkIBwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJEF5ibHLIjKQ4tEMD/j8VYxdY\n" +
                        "certif:         V6JM8rDokg+zNE4Ifc7nGaUrsrF2YRmcIg6OXVhPGLIqfQB2IsKub595sA1vgwNs\n" +
                        "certif:         +Cg0tzaQfzWh2Nz5NxFGnDHm5tPfOfiADwpMuLtZby390Wpbwk7VGZMqfcDXt3uy\n" +
                        "certif:         Ch4rvayDTtzQqDVqo1kLgK5dIc/UIlX3jaxWuI0EUOoKSgEEANYcEMxrEGD4LSgk\n" +
                        "certif:         vHVECSOB0q32CN/wSrvVzL6hP8RuO0gwwVQH1V8KCYiY6kDEk33Qb4f1bTo+Wbi6\n" +
                        "certif:         9yFvn1OvLh3/idb3U1qSq2+Y6Snl/kvgoVJQuS9x1NePtCYL2kheTAGiswg6CxTF\n" +
                        "certif:         RZ3c7CaNHsCbUdIpQmNUxfcWBH3PABEBAAGIpQQYAQIADwUCUOoKSgIbDAUJAAFR\n" +
                        "certif:         gAAKCRBeYmxyyIykON13BACeqmXZNe9H/SK2AMiFLIx2Zfyw/P0cKabn3Iaan7iF\n" +
                        "certif:         kSwrZQhF4571MBxb9U41Giiyza/t7vLQH1S+FYFUqfWCa8p1VQDRavi4wDgy2PDp\n" +
                        "certif:         ouhDqH+Mfkqb7yv40kYOUJ02eKkdgSgwTEcpfwq9GU4kJLVO5O3Y3nOEAx736gPQ\n" +
                        "certif:         xw==\n" +
                        "certif:         =XcVO\n" +
                        "certif:         -----END PGP PUBLIC KEY BLOCK-----\n" +
                        "mnt-by:         UPD-MNT\n" +
                        "source:         TEST"));

        assertThat(subject.isExpired(dateTimeProvider), is(true));
    }

    @Test
    public void notExpired() throws Exception {
        PgpPublicKeyWrapper subject = PgpPublicKeyWrapper.parse(pgpKeycert);

        assertThat(subject.isExpired(dateTimeProvider), is(false));
    }

    @Test
    public void isRevoked() throws Exception {
        try {
            PgpPublicKeyWrapper.parse(
                    RpslObject.parse(
                            "key-cert:       PGPKEY-A48E76B2\n" +
                            "method:         PGP\n" +
                            "owner:          Revoked <revoked@ripe.net>\n" +
                            "fingerpr:       D9A8 D291 0E72 DE20 FE50  C8FD FC24 50DF A48E 76B2\n" +
                            "certif:         -----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                            "certif:         Version: GnuPG v1.4.12 (Darwin)\n" +
                            "certif:         Comment: GPGTools - http://gpgtools.org\n" +
                            "certif:         \n" +
                            "certif:         mI0EUOtGSgEEALdT44Ijp/M+KUvuSjLR//SBhvAO1V+MzgpWPB6vSEZO8uSxAQCQ\n" +
                            "certif:         4gdXcsgpHjbcqe1KO00obtB74scD50l4sm9XPPr6tMK9I7MgwRlgRoJDWmw3lTFG\n" +
                            "certif:         7H1MSqI+RY9EcXTxbtfflfkoexvwIhheHge9OUNsdbgX4Su/Tv6KCVYxABEBAAGI\n" +
                            "certif:         nwQgAQIACQUCUOtIJwIdAgAKCRD8JFDfpI52spqaBACUfqolAt+ubV5+9hlF9RuD\n" +
                            "certif:         oE0B/OBmB/YwdNIs90s/zBwdiC8F6fB0dMJS0prFfOIJHCoMP6cSLUX83LjimNUk\n" +
                            "certif:         b6yYrNaFwAacWQaIA4lgw6GEsvo9tT0ZKZ7/tmcAl0uE3xJ5SyLMaJ5+2ayZ4U6O\n" +
                            "certif:         6r/ZepAn4V0+zJAecy8BabQaUmV2b2tlZCA8cmV2b2tlZEByaXBlLm5ldD6IuAQT\n" +
                            "certif:         AQIAIgUCUOtGSgIbAwYLCQgHAwIGFQgCCQoLBBYCAwECHgECF4AACgkQ/CRQ36SO\n" +
                            "certif:         drJJnwP+KU0nu8SfDb60Vvmhv2NceH5kPeAHJY3h4p6JSvo5b+RwjhxVQ2j7j4t2\n" +
                            "certif:         du9ozj+DrCpaQ4WfOttwg+wgFOSxhcV6y/o60BZMXCYf3DSP0wQiIC/w4vAQq1+U\n" +
                            "certif:         bNfDnGKhvJp7zob2BLTlpTi16APghTjnIXMVuUFfjFqURaemVT+4jQRQ60ZKAQQA\n" +
                            "certif:         1lvszl35cbExUezs+Uf2IoXrbqGNw4S7fIJogZigxeUkcgd+uK3aoL+zMlGOJuv1\n" +
                            "certif:         OyTh4rQfi+U99aVHQazRO4KSFsB1JjmlizRBkHtRJ5/4u5v8gzUa92Jj1MXHs0gS\n" +
                            "certif:         qQ0cCdRUMnZxcgg+4mYslUp2pC/vzk0II2HEnSQa/UsAEQEAAYifBBgBAgAJBQJQ\n" +
                            "certif:         60ZKAhsMAAoJEPwkUN+kjnay+jwEAJWGJFkFX1XdvGtbs7bPCdcMcJ3c/rj1vO91\n" +
                            "certif:         gNAjK/onsAzsBzsOSOx2eCEb4ftDASLmvnuK2h+lYLn5GOy0QpmCsZ37E3RcnhZq\n" +
                            "certif:         uKUMNY9A83YE8MV8MZXzds4p6XG1+YR7bP9nmgKqsLG9stCPAugVQqxVBbcQRsRV\n" +
                            "certif:         dnTzEonl\n" +
                            "certif:         =fnvN\n" +
                            "certif:         -----END PGP PUBLIC KEY BLOCK-----\n" +
                            "mnt-by:         UPD-MNT\n" +
                            "source:         TEST"));
            fail();
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage(), is("The supplied key is revoked"));
        }
    }

    //
    // test processing a revocation certificate to revoke a pgp key in a keycert object.
    //

    @Test
    public void revocationCerificate() throws Exception {
        final String publicKeyBlock =
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Comment: GPGTools - http://gpgtools.org\n" +
            "\n" +
            "mQENBFv0Nn4BCADGQGpCdloTOmVjaN5hjI89ECvrP6F2tMs0fH77tI3GprYuHkvS\n" +
            "35Q1PqR3D0TAdyuNRwrFqMxTZZT94bS3Nrq3ljskkeRm6Npic7DfGzFlvCYA4WJR\n" +
            "UXPuRARQ0ds25pVf8tUGpeJ/DG/y1nqh0keESOWF3R/yEghvZBE8zXWqNEIEso+u\n" +
            "id5hcahhkwCd6LzTX5xzjPxWU8N1Q7Lu2LNMGftHQfc7GyaYuH8hLu4HrJvckuiu\n" +
            "oF6gPuFq3EepXjH5BcxbmB4rka/5wnVu4qGJiLonqpWnhBlro2DvpxKluEbAH0oD\n" +
            "TzJSCIZKi3DZYNrMnTybrA9ITf0jpnIDQwK5ABEBAAG0GVRlc3QgVXNlciA8dGVz\n" +
            "dEByaXBlLm5ldD6JAVQEEwEIAD4WIQTqZ6Wh5dthPY/Wmdm1qXwMtBR2ugUCW/Q2\n" +
            "fgIbAwUJA8JnAAULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRC1qXwMtBR2ukAX\n" +
            "B/0V8PvB+p4MrhwuMDhqFmL0l/GcLoKiqUZSh7QpqOSzoIrwfdoOXcrJwBBe2fdH\n" +
            "m68u1LMP2+qokk5jrJ4e/vmSOVCBVUwABI2A9tTa9Z2WW3v0nCzm2w10NpmTcCUb\n" +
            "xEY1wsKBgXmCbxHxk7X0FwqlD6kXEaouJMfh7jF54GAj7mZwbysSzABsiHqX4fPr\n" +
            "wox8b5nbjSHI142kiWW1FxVUbraKnQJgPO6+E1ar4dap/Z9FkAChtffwlhcw80ic\n" +
            "zD2zBnG8c2Rsn7pkfT1qCDsYokvOjgD0L1viC/m+7WMyPzbY5FAnrW7I1JM/HUzg\n" +
            "I5wWpfXg1APL10eV9aqksz1EuQENBFv0Nn4BCAC8fJimY6pkcGpxWdxtKOJIlKFQ\n" +
            "hitADedWq4Gn9XsApSqIfHYODgKxJ2ZLiY+uhcU9tcfLf/1XQNslwdcTTG6dM+fF\n" +
            "W/lm5JtlD6vLOXb4igYYh1CdLrqFaFO9xvswlPgaXT3mWp7m61plyC167mJCbW1o\n" +
            "livLNd2z6JAJMbxSQaaZW1QaDz534AltmiX+dbtRKjNg5kfQffa14NkU7NCPLnAl\n" +
            "5UgjiKO2JNLl3onIIaT3a5cUV9qXACLBCiXoPfEZQqFR047f8TDCyiZupkdpWP5P\n" +
            "kJsAkC+MA/EMPeP7NXk4nqCWkjvAPXawMNRL77n9t/znA8Jgp0AWCLI2M1hfABEB\n" +
            "AAGJATwEGAEIACYWIQTqZ6Wh5dthPY/Wmdm1qXwMtBR2ugUCW/Q2fgIbDAUJA8Jn\n" +
            "AAAKCRC1qXwMtBR2ui43B/9taJHxhwT6TlJUQZZjcC+1gPcHqI7DYA+ADcn/U92I\n" +
            "zteWxEwlrkGnk0T57ay8ZqJCvlTJwmrHqG8VIkt6mARbg0X/onvwoAeu7zHYKfGP\n" +
            "kMPx5PbuqBhFG6YRuovgZB/URTSqeu0+sHJoCj4RAjvtkyD3gMH6AVss5irXxKDV\n" +
            "iSvGHUhD54reIJ1ypJjgeeDrH6C87v9RXSt98mbNIDMkkH4CpZ/+ixF6/7wENHJz\n" +
            "ePHgWgsRQGZidr9w0dHNgzK2CRzekS4enr1tofc3HdqxCoMw1Rh1l6FTDOEhK8el\n" +
            "6l8+hev49IP08e7zu5RTW8j0kyZFO1JqW9teOW5ooHRx\n" +
            "=zR5W\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";

        final PGPPublicKey masterKey = getMasterKey(publicKeyBlock);
        assertThat(masterKey.hasRevocation(), is(false));

        final String revocationCertificate =
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                    "Comment: GPGTools - http://gpgtools.org\n" +
                    "Comment: This is a revocation certificate\n" +
                    "\n" +
                    "iQE9BCABCAAnFiEE6meloeXbYT2P1pnZtal8DLQUdroFAlv0NrkJHQJUZXN0aW5n\n" +
                    "AAoJELWpfAy0FHa6/cQH/31Y/x9bA7BQcuEDNpRBuLZZ02/bkMzMQpCAQUxIzGmz\n" +
                    "kVoGTlYuktwX9K44phMIwVTz781AT3C1OsKxN3dX94y1oH6+63MEo/bB7G14mjeK\n" +
                    "0uxQKeiGlUdllA6VYyWhe3qMhqV19BJyicCIzwDxTTZqq8sYFqF179yqohORFJcn\n" +
                    "eKykwb2L83bIgbpLPN6kuAac8LP/TXO0WtxFFsbKIjwCQQL2o+guLdhjOPk2PZnj\n" +
                    "yrNy9825f6duOjV58usiNoGZ3MJOKohRjNZ75yHBap1BzNptTziL7xnyuKHE6Flm\n" +
                    "QjoB0E3anREe/pqjJWVkcf1/d39HkPeNa7t0Wk/bDC8=\n" +
                    "=Fu/+\n" +
                    "-----END PGP PUBLIC KEY BLOCK-----";

        final PGPSignature revocation = getRevocation(revocationCertificate);

         assertThat(revoke(masterKey, revocation).hasRevocation(), is(true));
    }

    private PGPPublicKey revoke(final PGPPublicKey pgpPublicKey, final PGPSignature revocation) {
        try {
            JcaPGPContentVerifierBuilderProvider provider = new JcaPGPContentVerifierBuilderProvider().setProvider(PROVIDER);
            revocation.init(provider, pgpPublicKey);

            if (!revocation.verifyCertification(pgpPublicKey)) {
                throw new IllegalStateException("Revocation certificate is not valid");
            }

            return PGPPublicKey.addCertification(pgpPublicKey, revocation);
        } catch (PGPException e) {
            throw new IllegalStateException(e);
        }
    }


    @Nullable
    private PGPPublicKey getMasterKey(final String block) {
        try {
            final ArmoredInputStream armoredInputStream = (ArmoredInputStream) PGPUtil.getDecoderStream(new ByteArrayInputStream(block.getBytes()));
            PGPPublicKey masterKey = null;
            List<PGPPublicKey> subKeys = Lists.newArrayList();

            @SuppressWarnings("unchecked")
            final Iterator<PGPPublicKeyRing> keyRingsIterator = new BcPGPPublicKeyRingCollection(armoredInputStream).getKeyRings();
            while (keyRingsIterator.hasNext()) {
                @SuppressWarnings("unchecked")
                final Iterator<PGPPublicKey> keyIterator = keyRingsIterator.next().getPublicKeys();
                while (keyIterator.hasNext()) {
                    final PGPPublicKey key = keyIterator.next();
                    if (key.isMasterKey()) {
                        if (masterKey == null) {
                            if (key.hasRevocation()) {
                                throw new IllegalArgumentException("The supplied key is revoked");
                            }

                            masterKey = key;
                        } else {
                            throw new IllegalArgumentException("The supplied object has multiple keys");
                        }
                    } else {
                        if (masterKey == null) {
                            continue;
                        }

                        if (key.isRevoked()) {
                            continue;
                        }

                        // RFC 4880: verify subkey binding signature issued by the top-level key
                        final Iterator<PGPSignature> signatureIterator = key.getSignaturesOfType(PGPSignature.SUBKEY_BINDING);
                        while (signatureIterator.hasNext()) {
                            final PGPSignature signature = signatureIterator.next();

                            if (!hasFlag(signature, PGPKeyFlags.CAN_SIGN)) {
                                // cannot sign with this subkey, skip it
                                continue;
                            }

                            JcaPGPContentVerifierBuilderProvider provider = new JcaPGPContentVerifierBuilderProvider().setProvider(PROVIDER);
                            signature.init(provider, masterKey);
                            try {
                                if (signature.verifyCertification(masterKey, key)) {
                                    subKeys.add(key);
                                }
                            } catch (PGPException e) {
                                throw new IllegalStateException(e);
                            }
                        }
                    }
                }
            }

            if (masterKey == null) {
                throw new IllegalArgumentException("The supplied object has no key");
            }

            return masterKey;

        } catch (IOException e) {
            throw new IllegalArgumentException("The supplied object has no key");
        } catch (PGPException e) {
            throw new IllegalArgumentException("The supplied object has no key");
        }
    }

    static boolean hasFlag(final PGPSignature signature, final int flag) {
        if (signature.hasSubpackets()) {
            PGPSignatureSubpacketVector subpacketVector = signature.getHashedSubPackets();
            if (subpacketVector.hasSubpacket(SignatureSubpacketTags.KEY_FLAGS)) {
                if ((subpacketVector.getKeyFlags() & flag) > 0) {
                    return true;
                }
            }
        }
        return false;
    }

    @Nullable
    private PGPSignature getRevocation(final String block) {
        try {
            final byte[] bytes = block.getBytes(Charsets.ISO_8859_1);
            final Iterator iterator = new BcPGPObjectFactory(PGPUtil.getDecoderStream(new ByteArrayInputStream(bytes))).iterator();
            while (iterator.hasNext()) {
                final Object next = iterator.next();
                if (next instanceof PGPSignatureList) {
                    for (PGPSignature pgpSignature : (PGPSignatureList)next) {
                        if (pgpSignature.getSignatureType() == PGPSignature.KEY_REVOCATION) {
                            return pgpSignature;
                        }
                    }
                }
            }
        } catch (IOException e) {
            // ignore
        }

        return null;
    }


    private String getResource(final String resourceName) throws IOException {
        return IOUtils.toString(new ClassPathResource(resourceName).getInputStream());
    }
}
