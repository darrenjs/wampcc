#include "Table.h"

#include <jalson/jalson.h>

#include <iostream>

namespace XXX {


/* Constructor */
Table::Table(const std::string & name)
  : Topic(name)

{
}

/* Destructor */
Table::~Table()
{
}



void Table::_nolock_add_column(const std::string & column,
                               std::list<jalson::json_array>& events)
{
  // Are we really adding a new column?
  bool adding_column = (m_column_index.find(column) == m_column_index.end());
  if (!adding_column) return;

  m_columns.push_back( column );

  jalson::json_array jv;
  jv.push_back("coladd");
  jalson::json_array columns;
  columns.push_back( column );
  jv.push_back(columns);
  events.push_back( jv );

  // rebuild column index
  m_column_index.clear();
  for (size_t i = 0; i < m_columns.size(); ++i)
    m_column_index[ m_columns[i] ] = i;

  // add column to every row - a default value is required, for which the
  // empty string is used.
  std::map<std::string, std::string> fields;
  fields[ column ] = "";

  // Note: not currently generating any events here. They might have to change
  // if we use json patch
  for (DataRow & r : m_rows)
  {
    r.add_column();
  }
}


void Table::add_columns(const std::vector<std::string>& cols)
{
  std::lock_guard<std::mutex> guard( m_tablelock );

  std::list< jalson::json_array > events;

  for (std::vector<std::string>::const_iterator it = cols.begin();
       it != cols.end(); ++it)
  {
    _nolock_add_column(*it, events);
  }

  if ( not events.empty() ) publish( events );
}


void Table::_nolock_add_row(const std::string& rowkey,
                            std::list<jalson::json_array>& events)
{
  m_rows.push_back( DataRow( rowkey  ) );
  m_rows.back().m_fields.resize(m_columns.size());
  m_rows.back().m_meta.resize(m_columns.size());

  // rebuild index
  m_row_index.clear();
  for (size_t i = 0; i < m_rows.size(); ++i)
  {
    m_row_index[ m_rows[i].rowkey() ] = i;
  }

  jalson::json_array event;
  event.push_back("rowadd");
  event.push_back(rowkey);
  event.push_back("\n");

  events.push_back( event );
}

void Table::add_row(const std::string& rowkey)
{
    std::list<jalson::json_array> events;


   std::lock_guard<std::mutex> guard( m_tablelock );

   auto it = m_row_index.find( rowkey );
   if ( it == m_row_index.end() ) return;

   _nolock_add_row( rowkey, events );

   if ( not events.empty() ) publish( events );
}


  void Table::update_row(const std::string& rowkey,
                         const std::string& fieldname,
                         const std::string& value)
  {
    std::list<jalson::json_array> events;

    std::lock_guard<std::mutex> guard( m_tablelock );

    // ensure the row exists -- TODO: this could be implemented far more
    // efficiently
    std::map< std::string, size_t >::iterator it = m_row_index.find( rowkey );
    if (it == m_row_index.end())
    {
      _nolock_add_row( rowkey, events );
      it = m_row_index.find( rowkey );
    }

    _nolock_add_column(fieldname, events);

    // get column index
    size_t colindex = m_column_index[fieldname];

    DataRow& row = m_rows[ it->second  ];
    row.m_fields[colindex] = value;


    jalson::json_array event;
    event.push_back("rowmod");
    event.push_back(rowkey);
    event.push_back(fieldname);
    event.push_back(value);

    events.push_back( event );

    if ( not events.empty() ) publish( events );
  }



//----------------------------------------------------------------------
void Table::clear_table()
{
  std::list<jalson::json_array> events;
  jalson::json_array event;
  std::lock_guard<std::mutex> guard( m_tablelock );

  event.push_back("clear");

  // TODO: what about rowkey column?
  m_rows.clear();
  m_row_index.clear();
  m_columns.clear();
  m_column_index.clear();

  if ( not events.empty() ) publish( events );
}




} // namespace XXX
