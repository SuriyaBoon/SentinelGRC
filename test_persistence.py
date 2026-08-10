import unittest
from unittest.mock import Mock
from persistence import Database, DatabaseConnection
class DatabaseReadinessTests(unittest.TestCase):
    def test_ping_returns_false_when_connection_acquisition_fails(self):
        database = Database.__new__(Database)
        database.connect = Mock(side_effect=RuntimeError("database unavailable"))
        self.assertFalse(database.ping())
    def test_broken_postgres_connection_is_closed_not_returned_to_pool(self):
        database = Database.__new__(Database)
        database.dialect = "postgresql"
        database._pool = Mock()
        raw_connection = Mock()
        raw_connection.rollback.side_effect = RuntimeError("connection lost")
        connection = DatabaseConnection(database, raw_connection)
        connection.close()
        raw_connection.close.assert_called_once_with()
        database._pool.putconn.assert_not_called()
if __name__ == "__main__":
    unittest.main()
