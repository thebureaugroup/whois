package net.ripe.db.whois.compare;

import com.google.common.base.Stopwatch;
import net.ripe.db.whois.common.ManualTest;
import net.ripe.db.whois.common.domain.ResponseObject;
import net.ripe.db.whois.common.support.QueryExecutorConfiguration;
import net.ripe.db.whois.common.support.TelnetWhoisClient;
import net.ripe.db.whois.compare.common.ComparisonExecutor;
import net.ripe.db.whois.compare.common.ComparisonExecutorConfig;
import net.ripe.db.whois.compare.common.ComparisonRunner;
import net.ripe.db.whois.compare.common.QueryReader;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.math.stat.descriptive.SummaryStatistics;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertNotNull;

@Category(ManualTest.class)
public class MeterTwoQueryInstancesByFile {

    @Test
    public void meter() {
        new MeteredComparisonRunner(
            new MeterTelnetComparisonExecutor(ComparisonExecutorConfig.PRE1),
            new MeterTelnetComparisonExecutor(ComparisonExecutorConfig.PRE2)).runCompareTest();
    }

    private static class MeteredComparisonRunner implements ComparisonRunner {

        private static final Logger LOGGER = LoggerFactory.getLogger(MeterTelnetComparisonExecutor.class);
        private static final int SAMPLES = 1_000;

        final MeterTelnetComparisonExecutor executor1;
        final MeterTelnetComparisonExecutor executor2;

        MeteredComparisonRunner(
                final MeterTelnetComparisonExecutor executor1,
                final MeterTelnetComparisonExecutor executor2) {
            this.executor1 = executor1;
            this.executor2 = executor2;
        }

        @Override
        public Future<List<ResponseObject>> executeQuery(final ComparisonExecutor queryExecutor, final String queryString) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void runCompareTest() {

            final QueryReader queryReader = new QueryReader(
                new ClassPathResource("comparison_queries")) {
                    @Override
                    protected String getQuery(final String line) {
                        return line;
                    }
                };

            for (final String queryString : queryReader.getQueries()) {

                if (StringUtils.isBlank(queryString) || queryString.startsWith("#")) {
                    continue;
                }

                final SummaryStatistics statistics1 = query(executor1, queryString);
                final SummaryStatistics statistics2 = query(executor2, queryString);

                LOGGER.info("{}\n\tEXECUTOR1 avg {} stddev {}\n\tEXECUTOR2 avg {} stddev {}",
                    queryString,
                    statistics1.getMean(), statistics1.getStandardDeviation(),
                    statistics2.getMean(), statistics2.getStandardDeviation());
            }
        }

        private SummaryStatistics query(final MeterTelnetComparisonExecutor executor, final String queryString) {
            final SummaryStatistics statistics = new SummaryStatistics();
            for (int count = 0; count < SAMPLES; count++) {
                final Stopwatch stopWatch = Stopwatch.createStarted();
                try {
                    assertNotNull(executor.getResponse(queryString));
                } finally {
                    statistics.addValue(stopWatch.elapsed(TimeUnit.MILLISECONDS));
                }
            }
            return statistics;
        }
    }

    private static class MeterTelnetComparisonExecutor implements ComparisonExecutor {

        private final TelnetWhoisClient telnetWhoisClient;

        MeterTelnetComparisonExecutor(final QueryExecutorConfiguration configuration) {
            this.telnetWhoisClient = new TelnetWhoisClient(configuration.getHost(), configuration.getQueryPort());
        }

        @Override
        public List<ResponseObject> getResponse(final String query) {
            telnetWhoisClient.sendQuery(query);
            return Collections.emptyList();
        }

        @Override
        public QueryExecutorConfiguration getExecutorConfig() {
            throw new UnsupportedOperationException();
        }
    }

}
