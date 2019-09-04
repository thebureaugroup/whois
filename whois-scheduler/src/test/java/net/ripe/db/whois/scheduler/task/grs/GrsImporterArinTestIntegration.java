package net.ripe.db.whois.scheduler.task.grs;

import com.google.common.io.Files;
import net.ripe.db.whois.common.DateTimeProvider;
import net.ripe.db.whois.common.IntegrationTest;
import net.ripe.db.whois.common.dao.jdbc.DatabaseHelper;
import net.ripe.db.whois.common.grs.AuthoritativeResourceData;
import net.ripe.db.whois.common.grs.AuthoritativeResourceImportTask;
import net.ripe.db.whois.common.iptree.IpTreeUpdater;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.common.support.FileHelper;
import net.ripe.db.whois.common.support.TelnetWhoisClient;
import net.ripe.db.whois.query.QueryServer;
import net.ripe.db.whois.scheduler.AbstractSchedulerIntegrationTest;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.annotation.DirtiesContext;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertThat;

@Category(IntegrationTest.class)
@DirtiesContext
public class GrsImporterArinTestIntegration extends AbstractSchedulerIntegrationTest {

    @Autowired GrsImporter grsImporter;
    @Autowired IpTreeUpdater ipTreeUpdater;

    @Autowired AuthoritativeResourceImportTask authoritativeResourceImportTask;
    @Autowired AuthoritativeResourceData authoritativeResourceData;
    @Autowired DateTimeProvider dateTimeProvider;

    private static final File tempDirectory = Files.createTempDir();
    private static final String ZIP_ENTRY_FILENAME = "arin_db.txt";

    @BeforeClass
    public static void setup_database() throws IOException {
        DatabaseHelper.addGrsDatabases("ARIN-GRS");

        final File resourceFile = FileHelper.addToTextFileWithMd5Checksum(tempDirectory, "ARIN-GRS-RES.tmp",
                "arin|*|asn|*|22831|summary\n" +
                "arin|*|ipv4|*|53557|summary\n" +
                "arin|*|ipv6|*|29780|summary\n" +
                "arin|US|asn|701|5|19900803|assigned|e220ed812a4c17f6a76b9b930dae7f50\n" +
                "arin|US|ipv4|198.151.193.0|256|20140414|allocated|35073\n" + // franken-range part 1
                "arin|US|ipv4|198.151.194.0|256|20140414|allocated|35073\n" + // franken-range part 2
                "arin|US|ipv4|12.45.82.0|256|20140414|allocated|35073\n"  );

        final File dumpFile = FileHelper.addToZipFile(
                tempDirectory,
                "ARIN-GRS-DMP.tmp",
                ZIP_ENTRY_FILENAME,
                        "\n" + "\n" +
                        "ASHandle:       AS701\n" +
                        "OrgID:          MCICS\n" +
                        "ASName:         UUNET\n" +
                        "ASNumber:       701 - 705\n" +
                        "RegDate:        1990-08-03\n" +
                        "Updated:        2012-03-20\n" +
                        "Source:         ARIN\n" +
                        "\n" +
                        "\n" +
                        "\n" +
                        "NetHandle:      NET-198-151-193-0-1\n" +
                        "OrgID:          TBL-353\n" +
                        "Parent:         NET-198-0-0-0-0\n" +
                        "NetName:        AMPFIN\n" +
                        "NetRange:       198.151.193.0 - 198.151.194.255\n" +
                        "NetType:        assignment\n" +
                        "RegDate:        1993-06-23\n" +
                        "Updated:        2012-04-02\n" +
                        "Source:         ARIN\n" +
                        "\n" +
                        "\n" +
                        "\n" +
                        "POCHandle:      SN34-ARIN\n" +
                        "IsRole:         N\n" +
                        "LastName:       Newman\n" +
                        "FirstName:      Stacy\n" +
                        "Street:         Congressional Budget Office\n" +
                        "Street:         2nd & D Streets, S.W.\n" +
                        "Street:         Ford Office Building #2, Room 486\n" +
                        "City:           Washington\n" +
                        "State/Prov:     DC\n" +
                        "Country:        US\n" +
                        "PostalCode:     20515\n" +
                        "RegDate:        1994-03-08\n" +
                        "Updated:        1994-03-09\n" +
                        "OfficePhone:    +1-202-226-2812\n" +
                        "Mailbox:        stacy.sdru@cbo.gov\n" +
                        "Source:         ARIN\n" +
                        "\n" +
                        "\n" +
                        "\n" +
                        "OrgID:          TBL-353\n" +
                        "OrgName:        TEST BVOIP COMPANY LL\n" +
                        "CanAllocate:    \n" +
                        "Street:         225 W RANDOLPH UNIT 01035\n" +
                        "City:           CHGO\n" +
                        "State/Prov:     IL\n" +
                        "Country:        US\n" +
                        "PostalCode:     99774\n" +
                        "RegDate:        2015-05-02\n" +
                        "Updated:        2015-05-02\n" +
                        "OrgAdminHandle: SHRES56-ARIN\n" +
                        "OrgAbuseHandle: SHRES56-ARIN\n" +
                        "OrgTechHandle:  SHRES56-ARIN\n" +
                        "Source:         ARIN\n" +
                        "\n" +
                        "\n" +
                        "\n" +
                        "POCHandle:      NOC32773-ARIN\n" +
                        "IsRole:         Y\n" +
                        "LastName:       Network Operation Center\n" +
                        "FirstName:      \n" +
                        "Street:         Avenida Vinte e Sete de Julho\n" +
                        "City:           Campina Grande\n" +
                        "State/Prov:     PB\n" +
                        "Country:        BR\n" +
                        "PostalCode:     58429-130\n" +
                        "RegDate:        2018-01-25\n" +
                        "Updated:        2018-01-25\n" +
                        "OfficePhone:    +551142007772\n" +
                        "Mailbox:        contato@hostzone.com.br\n" +
                        "Source:         ARIN\n" +
                        "\n" +
                        "\n" +
                        "\n" +
                        "NetHandle:      NET-12-45-82-160-1\n" +
                        "OrgID:          BB-1476\n" +
                        "Parent:         NET-12-0-0-0-1\n" +
                        "NetName:        BEST-BUY83-82-160\n" +
                        "NetRange:       12.45.82.160 - 12.45.82.167\n" +
                        "NetType:        reassignment\n" +
                        "RegDate:        2018-01-08\n" +
                        "Updated:        2018-01-08\n" +
                        "Source:         ARIN\n" +
                        "\n" +
                        "\n" +
                        "\n"
        );

        System.setProperty("grs.import.arin.source", "ARIN-GRS");
        System.setProperty("grs.import.arin.zipEntryName",ZIP_ENTRY_FILENAME);
        System.setProperty("grs.import.arin.download", getUrl(dumpFile));
        System.setProperty("grs.import.arin.resourceDataUrl", getUrl(resourceFile));
        System.setProperty("dir.grs.import.download", getPath(tempDirectory));
    }

    @AfterClass
    public static void cleanup() throws Exception {
        FileHelper.delete(tempDirectory);
    }

    @Before
    public void setUp() throws Exception {
        // initialize authoritativeresource
        authoritativeResourceImportTask.run();
        authoritativeResourceData.refreshAllSources();

        grsImporter.setGrsImportEnabled(true);
        queryServer.start();
    }

    @Test
    public void import_arin_grs() throws Exception {
        awaitAll(grsImporter.grsImport("ARIN-GRS", false));
        ipTreeUpdater.rebuild();

        awaitAll(grsImporter.grsImport("ARIN-GRS", false));
        ipTreeUpdater.rebuild();

        assertThat(query("-s ARIN-GRS AS701"), containsString("aut-num:        AS701"));
        assertThat(query("-s ARIN-GRS AS705"), containsString("aut-num:        AS705"));
        assertThat(query("-s ARIN-GRS 198.151.193.0"), containsString("status:         ASSIGNMENT"));
        assertThat(query("-s ARIN-GRS 198.151.193.0 - 198.151.193.255"), containsString("status:         ASSIGNMENT"));
        assertThat(query("-s ARIN-GRS 198.151.193.0 - 198.151.194.255"), containsString("status:         ASSIGNMENT"));
        assertThat(query("-s ARIN-GRS 198.151.193.0 - 198.151.194.255"), not(containsString("changed:")));
//
        assertThat(query("-s ARIN-GRS NOC32773-ARIN"), containsString("role:           Network Operation Center"));
//        databaseHelper.dumpSchema(whoisTemplate.getDataSource());
//        assertThat(query("-s ARIN-GRS TBL-353"), containsString("organisation:        TBL-353"));
        assertThat(query("-s ARIN-GRS SN34-ARIN"), containsString("person:         Stacy Newman"));


        assertThat(query("-s ARIN-GRS 88.202.240.0"), containsString("No entries found"));
        assertThat(query("-s APNIC-GRS 88.202.224.0 - 88.202.239.255"),  containsString("unknown source"));
    }

    @Test
    public void import_nethandle() throws Exception {

        databaseHelper.addObjectToSource("ARIN-GRS", RpslObject.parse("" +
            "inetnum:         12.45.82.160 - 12.45.82.167\n" +
//            "org:             BB-1476\n" +
            "netname:         BEST-BUY83-82-160\n" +
            "status:          REASSIGNMENT\n" +
            "source:          ARIN-GRS")
        );

        FileHelper.addToZipFile(
            tempDirectory,
            "ARIN-GRS-DMP.tmp",
            ZIP_ENTRY_FILENAME,
        "\n" + "\n" +
                "NetHandle:      NET-12-45-82-160-1\n" +
                "OrgID:          BB-1476\n" +
                "Parent:         NET-12-0-0-0-1\n" +
                "NetName:        BEST-BUY83-82-160\n" +
                "NetRange:       12.45.82.160 - 12.45.82.167\n" +
                "NetType:        reassignment\n" +
                "RegDate:        2018-01-08\n" +
                "Updated:        2018-01-08\n" +
                "Source:         ARIN" +
                "\n" +
                "\n" +
                "\n"
        );

        awaitAll(grsImporter.grsImport("ARIN-GRS", false));
        ipTreeUpdater.rebuild();

    }

    private void awaitAll(final List<Future> futures) throws ExecutionException, InterruptedException {
        for (final Future<?> future : futures) {
            future.get();
        }
    }

    private String query(final String query) throws Exception {
        return TelnetWhoisClient.queryLocalhost(QueryServer.port, query);
    }

    private static String getUrl(final File file) throws MalformedURLException {
        return file.toURI().toURL().toString();
    }

    private static String getPath(final File file) {
        return file.getAbsolutePath();
    }
}
