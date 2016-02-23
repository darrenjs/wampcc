#ifndef XXX_TABLE_H
#define XXX_TABLE_H

#include "Topic.h"

#include <jalson/jalson.h>

#include <vector>
#include <mutex>
#include <map>
#include <list>


namespace XXX {

  class Table;

  struct TableEventPtr
  {
  };

  struct Meta
  {
  };

  class DataRow
  {
  public:

    const std::string& rowkey() const { return m_rowkey; }

    explicit DataRow(const std::string& rowkey)
      : m_rowkey(rowkey)
    {
    }

    void add_column()
    {
      m_fields.push_back("");
      m_meta.push_back(Meta());
    }

    std::string m_rowkey;
    std::vector<std::string> m_fields;
    std::vector<Meta> m_meta;

  };

  class Table : public Topic
  {
  public:
    Table(const std::string &);
    ~Table();

    // TODO: need the copy interfaces, and other getters

    void add_columns(const std::vector<std::string>& cols);

    void add_row(const std::string& rowkey);

    void update_row(const std::string& rowkey,
                    const std::string& fieldname,
                    const std::string& value);

    void update_row(const std::string & rowkey,
                    const std::map<std::string, std::string> & fields);

    void clear_table();

    void delete_row() {}

  private:
    Table(const Table&) = delete;
    Table& operator=(const Table&) = delete;

    void _nolock_add_column(const std::string & column,
                            std::list<jalson::json_array>& events);


    void _nolock_add_row(const std::string& rowkey,
                         std::list<jalson::json_array>& events);

  private:


    // Note: if ever the subscriber-lock and table-lock have to be held at the
    // same time, then the table-lock must be locked first, followed by the
    // subscribers-lock
    mutable std::mutex m_tablelock; // big table lock

    std::vector< std::string >      m_columns;
    std::map< std::string, size_t > m_column_index;


    std::vector< DataRow >          m_rows;
    std::map< std::string, size_t > m_row_index;

  };

} // namespace XXX

#endif
