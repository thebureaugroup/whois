package net.ripe.db.whois.common.dao;

import net.ripe.db.whois.common.domain.Status;
import net.ripe.db.whois.common.iptree.IpEntry;

import java.util.List;

public interface StatusDao {

    Status getStatus(Integer objectId);

    List<Status> getStatus(List<IpEntry> entries);

}
