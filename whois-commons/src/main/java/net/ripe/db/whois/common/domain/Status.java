package net.ripe.db.whois.common.domain;

import javax.annotation.concurrent.Immutable;

@Immutable
public class Status {

    private final int objectId;
    private final CIString value;

    public Status(final CIString value, final int objectId) {
        this.value = value;
        this.objectId = objectId;
    }

    public Status(final String value, final int objectId) {
        this(CIString.ciString(value), objectId);
    }

    public CIString getValue() {
        return this.value;
    }

    public int getObjectId() {
        return this.objectId;
    }

}
