package net.ripe.db.whois.scheduler.task.grs;

import net.ripe.db.whois.common.DateTimeProvider;
import net.ripe.db.whois.common.grs.AuthoritativeResourceData;
import net.ripe.db.whois.common.domain.io.Downloader;
import net.ripe.db.whois.common.jdbc.DataSourceFactory;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.common.source.SourceContext;
import net.ripe.db.whois.common.support.FileHelper;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.io.File;

import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.Assert.assertThat;

@RunWith(MockitoJUnitRunner.class)
public class ArinGrsSourceTest {
    @Mock SourceContext sourceContext;
    @Mock DataSourceFactory dataSourceFactory;
    @Mock DateTimeProvider dateTimeProvider;
    @Mock AuthoritativeResourceData authoritativeResourceData;
    @Mock Downloader downloader;

    ArinGrsSource subject;
    CaptureInputObjectHandler objectHandler;

    @Before
    public void setUp() throws Exception {
        objectHandler = new CaptureInputObjectHandler();
        subject = new ArinGrsSource("ARIN-GRS", sourceContext, dateTimeProvider, authoritativeResourceData, downloader, "", "arin_db.txt");
    }

    @Test
    public void handleObjects() throws Exception {
        final File file = new File(getClass().getResource("/grs/arin.test.zip").toURI());

        subject.handleObjects(file, objectHandler);

        assertThat(objectHandler.getLines(), hasSize(0));
        assertThat(objectHandler.getObjects(), hasSize(7));
        assertThat(objectHandler.getObjects(), contains(
                RpslObject.parse("" +
                        "aut-num:        AS0\n" +
                        "org:            IANA\n" +
                        "as-name:        IANA-RSVD-0\n" +
                        "remarks:        Reserved - May be used to identify non-routed networks\n" +
                        "source:         ARIN\n"),

                RpslObject.parse("" +
                        "person:         Stacy Newman\n" +
                        "nic-hdl:        SN34-ARIN\n" +
                        "address:        Congressional Budget Office # street\n" +
                        "address:        2nd & D Streets, S.W. # street\n" +
                        "address:        Ford Office Building #2, Room 486 # street\n" +
                        "address:        Washington # city\n" +
                        "address:        DC # stateprov\n" +
                        "address:        US # country\n" +
                        "address:        20515 # postalcode\n" +
                        "phone:          +1-202-226-2812\n" +
                        "e-mail:         stacy.sdru@cbo.gov\n" +
                        "source:         ARIN\n"),

                RpslObject.parse("" +
                        "inetnum:        192.104.33.0 - 192.104.33.255\n" +
                        "org:            THESPI\n" +
                        "netname:        SPINK\n" +
                        "status:         assignment\n" +
                        "source:         ARIN\n"),

                RpslObject.parse("" +
                        "inet6num:       2001:4d0::/32\n" +
                        "org:            NASA\n" +
                        "netname:        NASA-PCCA-V6\n" +
                        "status:         allocation\n" +
                        "tech-c:         ZN7-ARIN\n" +
                        "source:         ARIN\n"),

                RpslObject.parse("" +
                        "inet6num:       2001:468:400::/40\n" +
                        "org:            V6IU\n" +
                        "netname:        ABILENE-IU-V6\n" +
                        "status:         reallocation\n" +
                        "tech-c:         BS69-ARIN\n" +
                        "source:         ARIN\n"),

                RpslObject.parse("" +
                        "organisation:   TBL-353\n" +
                        "org-name:       TEST BVOIP COMPANY LL\n" +
                        "address:        225 W RANDOLPH UNIT 01035 # street\n" +
                        "address:        CHGO # city\n" +
                        "address:        IL # stateprov\n" +
                        "address:        US # country\n" +
                        "address:        99774 # postalcode\n" +
                        "admin-c:        SHRES56-ARIN\n" +
                        "abuse-c:        SHRES56-ARIN\n" +
                        "tech-c:         SHRES56-ARIN\n" +
                        "source:         ARIN"),

                RpslObject.parse("" +
                        "role:           Network Operation Center\n" +
                        "nic-hdl:        NOC32773-ARIN\n" +
                        "address:        Avenida Vinte e Sete de Julho # street\n" +
                        "address:        Campina Grande # city\n" +
                        "address:        PB # stateprov\n" +
                        "address:        BR # country\n" +
                        "address:        58429-130 # postalcode\n" +
                        "phone:          +551142007772\n" +
                        "e-mail:         contato@hostzone.com.br\n" +
                        "source:         ARIN\n")
        ));
    }

    @Test
    @Ignore
    public void test_organisation() throws Exception {
        File zipFile = FileHelper.addToZipFile("arin.test", "arin_db.txt",
                "OrgID:          SILICO\n" +
                        "OrgName:        Silicon Engines Incorporated\n" +
                        "CanAllocate:    \n" +
                        "Street:         955 Commercial Street\n" +
                        "City:           Palo Alto\n" +
                        "State/Prov:     CA\n" +
                        "Country:        US\n" +
                        "PostalCode:     94303\n" +
                        "RegDate:        1991-04-11\n" +
                        "Updated:        2011-09-24\n" +
                        "OrgTechHandle:  DM507-ARIN\n" +
                        "OrgAbuseHandle: DM507-ARIN\n" +
                        "OrgAdminHandle: DM507-ARIN\n" +
                        "Source:         ARIN\n");

        try {
            subject.handleObjects(zipFile, objectHandler);

            assertThat(objectHandler.getLines(), hasSize(0));
            assertThat(objectHandler.getObjects(), hasSize(1));
            assertThat(objectHandler.getObjects(), contains(
                    RpslObject.parse(
                            "aut-num:        AS701\n" +
                                    "org:            MCICS\n" +
                                    "as-name:        UUNET\n" +
                                    "source:         ARIN"),
                    RpslObject.parse(
                            "aut-num:        AS702\n" +
                                    "org:            MCICS\n" +
                                    "as-name:        UUNET\n" +
                                    "source:         ARIN"),
                    RpslObject.parse(
                            "aut-num:        AS703\n" +
                                    "org:            MCICS\n" +
                                    "as-name:        UUNET\n" +
                                    "source:         ARIN"),
                    RpslObject.parse(
                            "aut-num:        AS704\n" +
                                    "org:            MCICS\n" +
                                    "as-name:        UUNET\n" +
                                    "source:         ARIN"),
                    RpslObject.parse(
                            "aut-num:        AS705\n" +
                                    "org:            MCICS\n" +
                                    "as-name:        UUNET\n" +
                                    "source:         ARIN")
            ));
        } finally {
            zipFile.delete();
        }

    }

    @Test
    public void as_number_range() throws Exception {
        File zipFile = FileHelper.addToZipFile("arin.test", "arin_db.txt",
                "ASHandle:       AS701\n" +
                "OrgID:          MCICS\n" +
                "ASName:         UUNET\n" +
                "ASNumber:       701 - 705\n" +
                "RegDate:        1990-08-03\n" +
                "Updated:        2012-03-20\n" +
                "Source:         ARIN\n");

        try {
            subject.handleObjects(zipFile, objectHandler);

            assertThat(objectHandler.getLines(), hasSize(0));
            assertThat(objectHandler.getObjects(), hasSize(5));
            assertThat(objectHandler.getObjects(), contains(
                    RpslObject.parse(
                            "aut-num:        AS701\n" +
                            "org:            MCICS\n" +
                            "as-name:        UUNET\n" +
                            "source:         ARIN"),
                    RpslObject.parse(
                            "aut-num:        AS702\n" +
                            "org:            MCICS\n" +
                            "as-name:        UUNET\n" +
                            "source:         ARIN"),
                    RpslObject.parse(
                            "aut-num:        AS703\n" +
                            "org:            MCICS\n" +
                            "as-name:        UUNET\n" +
                            "source:         ARIN"),
                    RpslObject.parse(
                            "aut-num:        AS704\n" +
                            "org:            MCICS\n" +
                            "as-name:        UUNET\n" +
                            "source:         ARIN"),
                    RpslObject.parse(
                            "aut-num:        AS705\n" +
                            "org:            MCICS\n" +
                            "as-name:        UUNET\n" +
                            "source:         ARIN")
                    ));
        } finally {
            zipFile.delete();
        }
    }

    @Test
    public void single_as_number() throws Exception {
        File zipFile = FileHelper.addToZipFile("arin.test", "arin_db.txt",
                "ASHandle:       AS701\n" +
                "OrgID:          MCICS\n" +
                "ASName:         UUNET\n" +
                "ASNumber:       701\n" +
                "RegDate:        1990-08-03\n" +
                "Updated:        2012-03-20\n" +
                "Source:         ARIN\n");

        try {
            subject.handleObjects(zipFile, objectHandler);

            assertThat(objectHandler.getLines(), hasSize(0));
            assertThat(objectHandler.getObjects(), hasSize(1));
            assertThat(objectHandler.getObjects(), contains(
                    RpslObject.parse(
                            "aut-num:        AS701\n" +
                            "org:            MCICS\n" +
                            "as-name:        UUNET\n" +
                            "source:         ARIN")));
        } finally {
            zipFile.delete();
        }
    }

    @Test
    public void as_number_without_range() throws Exception {
        File zipFile = FileHelper.addToZipFile("arin.test", "arin_db.txt",
                "ASHandle:       AS701\n" +
                "OrgID:          MCICS\n" +
                "ASName:         UUNET\n" +
                "RegDate:        1990-08-03\n" +
                "Updated:        2012-03-20\n" +
                "Source:         ARIN\n");

        try {
            subject.handleObjects(zipFile, objectHandler);

            assertThat(objectHandler.getLines(), hasSize(0));
            assertThat(objectHandler.getObjects(), hasSize(1));
            assertThat(objectHandler.getObjects(), contains(
                    RpslObject.parse(
                            "aut-num:        AS701\n" +
                            "org:            MCICS\n" +
                            "as-name:        UUNET\n" +
                            "source:         ARIN")));
        } finally {
            zipFile.delete();
        }
    }

}
