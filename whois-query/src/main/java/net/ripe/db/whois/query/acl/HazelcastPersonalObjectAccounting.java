package net.ripe.db.whois.query.acl;

import com.google.common.base.Stopwatch;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.IMap;
import com.hazelcast.core.OperationTimeoutException;
import com.hazelcast.map.EntryBackupProcessor;
import com.hazelcast.map.EntryProcessor;
import net.ripe.db.whois.common.profiles.DeployedProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.net.InetAddress;
import java.util.Map;

@DeployedProfile
@Primary
@Component
public class HazelcastPersonalObjectAccounting implements PersonalObjectAccounting {
    private static final Logger LOGGER = LoggerFactory.getLogger(HazelcastPersonalObjectAccounting.class);

    private static IMap<InetAddress, Integer> counterMap;

    private static volatile HazelcastInstance instance;

    static synchronized void startHazelcast() {
        if (instance != null) {
            throw new IllegalStateException("Hazelcast already started");
        }

        instance = Hazelcast.newHazelcastInstance(null);
        counterMap = instance.getMap("queriedPersonal");
    }

    static void shutdownHazelcast() {
        LOGGER.debug("Shutting down hazelcast instance");

        instance.getLifecycleService().shutdown();
        instance = null;
    }

    @PostConstruct
    public void startService() {
        startHazelcast();
    }

    @PreDestroy
    public void stopService() {
        shutdownHazelcast();
    }

    @Override
    public int getQueriedPersonalObjects(final InetAddress remoteAddress) {
        final Stopwatch stopwatch = Stopwatch.createStarted();
        Integer count = null;
        try {
            count = counterMap.get(remoteAddress);
        } catch (OperationTimeoutException e) {
            // prevents user from seeing "internal server error"
        }

        if (count == null) {
            return 0;
        }

        LOGGER.warn("Get {} for {} in {}", count, remoteAddress, stopwatch);
        return count;
    }

    @Override
    public int accountPersonalObject(final InetAddress remoteAddress, final int amount) {
        final Stopwatch stopwatch = Stopwatch.createStarted();

        final Integer result = (Integer)counterMap.executeOnKey(remoteAddress, new EntryProcessor<InetAddress, Integer>() {
            @Override
            public Integer process(Map.Entry<InetAddress, Integer> entry) {
                Integer count = entry.getValue();

                if (count == null) {
                    count = amount;
                } else {
                    count += amount;
                }

                entry.setValue(count);

                return count;
            }

            @Override
            public EntryBackupProcessor getBackupProcessor() {
                return null;
            }
        });

        LOGGER.warn("Account {} for {} in {}", result, remoteAddress, stopwatch);

        return result;
    }

    @Override
    public void resetAccounting() {
        LOGGER.debug("Reset person object counters ({} entries)", counterMap.size());
        counterMap.clear();
    }
}
