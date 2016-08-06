#ifndef XXX_UTILS_H
#define XXX_UTILS_H

#include <sstream>
#include <list>
#include <random>
#include <memory>

#define THROW(E, X )  do                        \
  {                                             \
    std::ostringstream __os;                    \
    __os << X ;                                 \
    throw E ( __os.str() );                     \
  } while(false);


namespace XXX {

struct logger;

enum class HMACSHA256_Mode
{
  HEX,
  BASE64
};

int compute_HMACSHA256(const char* key,
                       int keylen,
                       const char* msg,
                       int msglen,
                       char * dest,
                       unsigned int * destlen,
                       HMACSHA256_Mode output_mode);


/* must be called with an active exception */
void log_exception(logger &__logptr, const char* callsite);


/* Generate iso8601 timestamp, like YYYY-MM-DDThh:mm:ss.sssZ */
std::string iso8601_utc_timestamp();

/* Generate a random string of ascii printables of length 'len' */
std::string random_ascii_string(const size_t len,
                                unsigned int seed = std::random_device()());

/* Implements a general list of observers, which can be notified with a generic
 * function with variadic arguments. Observer objects should be plain structs
 * that consist of a set of std::function members. */
template<typename T>
class observer_list
{
public:
  struct key {};

  /* Add observer, returning a unique key used for later removal. */
  key* add(T&& obs)
  {
    m_observers.emplace_back(std::unique_ptr<key>(new key()), std::move(obs));
    return m_observers.back().first.get();
  }

  /* Notify observers, by applying a functional object, with supplied
   * arguments. */
  template<typename F, typename... Args>
  void notify(const F& fn, Args&&... args)
  {
    for (auto & item : m_observers)
      fn( item.second, args... );
  }

  void remove(key* const k)
  {
    for (auto it = m_observers.begin();
         it != m_observers.end(); ++it)
    {
      if (k == it->first.get())
      {
        m_observers.erase(it);
        return;
      }
    }
  }

  size_t size()  const { return m_observers.size(); }
  bool   empty() const { return m_observers.empty(); }

private:
  std::vector<std::pair< std::unique_ptr<key>, T>> m_observers;
};


struct regex_impl;
class uri_regex
{
public:
  uri_regex();
  ~uri_regex();

  uri_regex(const uri_regex &) = delete;
  uri_regex& operator=(const uri_regex &) = delete;

  bool is_strict_uri(const char*) const;

private:
  regex_impl * m_impl;

};

} // namespace XXX

#endif
