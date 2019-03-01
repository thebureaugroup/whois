package net.ripe.db.whois.common.dao.jdbc;

import net.ripe.db.whois.common.rpsl.AttributeType;

public interface IndexDao {
    void rebuild();

    void rebuild(final AttributeType attributeType);

    void rebuildForObject(int objectId);

    void pause();

    void resume();
}
