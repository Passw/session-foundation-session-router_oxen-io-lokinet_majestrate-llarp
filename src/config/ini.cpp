#include "ini.hpp"

#include "util/file.hpp"
#include "util/formattable.hpp"
#include "util/logging.hpp"

#include <cctype>
#include <list>
#include <stdexcept>

namespace srouter
{
    static auto logcat = log::Cat("config.ini");

    void ConfigParser::load_file(const std::filesystem::path& fname)
    {
        _data = util::file_to_string(fname);
        _file_desc = util::path_as_str(fname);
        parse();
    }

    void ConfigParser::load_from_str(std::string str)
    {
        _data = str;
        parse();
    }

    void ConfigParser::clear()
    {
        _config.clear();
        _data.clear();
    }

    static bool whitespace(char ch) { return std::isspace(static_cast<unsigned char>(ch)) != 0; }

    void ConfigParser::parse()
    {
        std::list<std::string_view> lines;
        {
            auto itr = _data.begin();
            // split into lines
            while (itr != _data.end())
            {
                auto beg = itr;
                while (itr != _data.end() && *itr != '\n' && *itr != '\r')
                    ++itr;
                lines.emplace_back(std::addressof(*beg), std::distance(beg, itr));
                if (itr == _data.end())
                    break;
                ++itr;
            }
        }

        std::string_view sectName;
        size_t lineno = 0;
        for (auto line : lines)
        {
            lineno++;
            // Trim whitespace
            while (!line.empty() && whitespace(line.front()))
                line.remove_prefix(1);
            while (!line.empty() && whitespace(line.back()))
                line.remove_suffix(1);

            // Skip blank lines
            if (line.empty() or line.front() == ';' or line.front() == '#')
                continue;

            if (line.front() == '[' && line.back() == ']')
            {
                // section header
                line.remove_prefix(1);
                line.remove_suffix(1);
                sectName = line;
            }
            else if (auto kvDelim = line.find('='); kvDelim != std::string_view::npos)
            {
                // key value pair
                std::string_view k = line.substr(0, kvDelim);
                std::string_view v = line.substr(kvDelim + 1);
                // Trim inner whitespace
                while (!k.empty() && whitespace(k.back()))
                    k.remove_suffix(1);
                while (!v.empty() && whitespace(v.front()))
                    v.remove_prefix(1);

                if (k.empty())
                {
                    throw std::runtime_error(fmt::format("{} invalid line ({}): '{}'", _file_desc, lineno, line));
                }

                log::debug(logcat, "{}:[{}]:{}={}", _file_desc, sectName, k, v);
                _config[std::string{sectName}][std::string{k}].emplace_back(v);
            }
            else  // malformed?
            {
                throw std::runtime_error(fmt::format("{} invalid line ({}): '{}'", _file_desc, lineno, line));
            }
        }
    }

    void ConfigParser::iter_all_sections(std::function<void(std::string_view, const SectionValues&)> visit)
    {
        for (const auto& item : _config)
            visit(item.first, item.second);
    }

    bool ConfigParser::visit_section(const char* name, std::function<bool(const SectionValues& sect)> visit) const
    {
        // m_Config is effectively:
        // unordered_map< string, unordered_multimap< string, string  >>
        // in human terms: a map of of sections
        //                 where a section is a multimap of k:v pairs
        auto itr = _config.find(name);
        if (itr == _config.end())
            return false;
        return visit(itr->second);
    }

}  // namespace srouter
