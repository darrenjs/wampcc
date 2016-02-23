#ifndef XXX_SID_H
#define XXX_SID_H

#include <Callbacks.h>

#include <ostream>
#include <stdint.h>

namespace XXX {

/* Information about a session that once set, will never change, and is used to
 * uniquely identify it. */
class SID
{
public:
   static SID null_sid;

  /* Creates the null session */
  SID() : m_unqiue_id(0) { }

  explicit SID(unsigned int s) : m_unqiue_id( s) { }

  bool operator==(SID rhs) const
  {
    return (this->m_unqiue_id == rhs.m_unqiue_id);
  }

  bool operator<(SID rhs) const
  {
    return this->m_unqiue_id < rhs.m_unqiue_id;
  }

  //std::string to_string() const;
  //static SID from_string(const std::string&);

  size_t unique_id() const { return m_unqiue_id; }

private:
  t_sid m_unqiue_id;

  friend std::ostream& operator<<(std::ostream&, const SID &);
};

std::ostream& operator<<(std::ostream&, const SID &);


} // namespace XXX

#endif
