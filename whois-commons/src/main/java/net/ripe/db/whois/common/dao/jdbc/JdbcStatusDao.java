package net.ripe.db.whois.common.dao.jdbc;

import net.ripe.db.whois.common.aspects.RetryFor;
import net.ripe.db.whois.common.dao.StatusDao;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.domain.Status;
import net.ripe.db.whois.common.iptree.IpEntry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.RecoverableDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import javax.sql.DataSource;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

@Repository
@RetryFor(RecoverableDataAccessException.class)
public class JdbcStatusDao implements StatusDao {

    private final JdbcTemplate jdbcTemplate;
    private final NamedParameterJdbcTemplate namedParameterJdbcTemplate;

    @Autowired
    public JdbcStatusDao(@Qualifier("sourceAwareDataSource") final DataSource dataSource) {
        this.jdbcTemplate = new JdbcTemplate(dataSource);
        this.namedParameterJdbcTemplate = new NamedParameterJdbcTemplate(jdbcTemplate);
    }

    @Override
    public Status getStatus(final Integer objectId) {
        return jdbcTemplate.queryForObject(
                "SELECT object_id, status " +
                "FROM status " +
                "WHERE object_id = ?",
                new StatusRowMapper(),
                objectId);
    }

    @Override
    public List<Status> getStatus(final List<IpEntry> entries) {
        return null;
    }


    private static class StatusRowMapper implements RowMapper<Status> {
        @Override
        public Status mapRow(final ResultSet rs, final int rowNum) throws SQLException {
            final int objectId = rs.getInt(1);
            final CIString value = CIString.ciString(rs.getString(2));
            return new Status(value, objectId);
        }
    }

}
