/*
    Copyright 2013, Darren Smith

    This file is part of exio, a library for providing administration,
    monitoring and alerting capabilities to an application.

    exio is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    exio is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with exio.  If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef EXIO_LOGINTERFACE_H
#define EXIO_LOGINTERFACE_H

#include <string>
#include <sstream>

#include <functional>
#include <memory>
#include <mutex>


#define _DEBUG_( X )                                           \
  do {                                                         \
    if ( __logptr and __logptr->want_debug() )                 \
    {                                                          \
      std::ostringstream __xx_oss;                             \
      __xx_oss <<  X ;                              \
      __logptr->debug( __xx_oss.str(),__FILE__,__LINE__  ) ;   \
    }                                                          \
  } while (0)


#define _INFO_( X )                                           \
  do {                                                        \
    if ( __logptr and __logptr->want_info() )                 \
    {                                                         \
      std::ostringstream __xx_oss;                            \
      __xx_oss <<  X ;                             \
      __logptr->info( __xx_oss.str(),__FILE__,__LINE__  ) ;   \
    }                                                         \
  } while (0)

#define _WARN_( X )                                            \
  do {                                                         \
    if ( __logptr and __logptr->want_warn() )                  \
    {                                                          \
      std::ostringstream __xx_oss;                             \
      __xx_oss <<  X ;                              \
      __logptr->warn( __xx_oss.str(),__FILE__,__LINE__  ) ;    \
    }                                                          \
  } while(0)

#define _ERROR_( X )                                           \
  do {                                                         \
    if ( __logptr and __logptr->want_error() )                 \
    {                                                          \
      std::ostringstream __xx_oss;                             \
      __xx_oss <<  X ;                              \
      __logptr->error( __xx_oss.str(),__FILE__,__LINE__  ) ;   \
    }                                                          \
  } while(0)


namespace XXX
{


class logger
{
public:
  enum Level {eNone = 0,
              eError,
              eWarn,
              eInfo,
              eDebug,
              eAll = 255};

  logger(int l) : m_level(l) {}
  virtual ~logger() {}

  virtual void debug(const char*, const char* /*file*/, int /*ln*/) {};
  virtual void info(const char*,  const char* /*file*/, int /*ln*/) {};
  virtual void warn(const char*,  const char* /*file*/, int /*ln*/) {};
  virtual void error(const char*, const char* /*file*/, int /*ln*/) {};

  virtual void debug(const std::string& msg, const char* file, int ln)
  {
    debug(msg.c_str(), file, ln);
  }
  virtual void info(const std::string& msg,  const char* file, int ln)
  {
    info(msg.c_str(), file, ln);
  }
  virtual void warn(const std::string& msg,  const char* file, int ln)
  {
    warn(msg.c_str(), file, ln);
  }
  virtual void error(const std::string& msg, const char* file, int ln)
  {
    error(msg.c_str(), file, ln);
  }


  bool want_debug() const { return m_level >= eDebug; }
  bool want_info()  const { return m_level >= eInfo; }
  bool want_warn()  const { return m_level >= eWarn; }
  bool want_error() const { return m_level >= eError; }

  std::function<bool(Level)> log_want;
  std::function<void(Level, const char*, const char* file, int ln)> log_send;


protected:
  int  m_level;
};


class ConsoleLoggerImpl;
class ConsoleLogger : public logger
{
public:
  enum StreamType { eStdout, eStderr };

  ConsoleLogger(StreamType stream,
                int level,
                bool incsource=false);
  ~ConsoleLogger();

  virtual void debug(const char*, const char* file, int ln);
  virtual void info(const char*,  const char* file, int ln);
  virtual void warn(const char*,  const char* file, int ln);
  virtual void error(const char*, const char* file, int ln);

private:
  void dolog(const char*, const char*, const char*, int);
  ConsoleLoggerImpl * m_impl;

private:
  ConsoleLogger(const ConsoleLogger&);
  ConsoleLogger& operator=(const ConsoleLogger&);
};


} // namespace



#endif
