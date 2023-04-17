#include <bits/stdc++.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cmath>

#define BOOST_BIND_GLOBAL_PLACEHOLDERS

#include <boost/beast.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#define BOOST_LOG_DYN_LINK 1

#include <boost/log/trivial.hpp>
#include <ctime>

unsigned int start_time;
unsigned int end_time;
int local_start_time;


#define SIZE_ETHERNET 14 // длина интернет заголовка - обычно, 14 байт
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
using namespace std;

namespace http = boost::beast::http;
const static string mainApi = "ip-api.com";
const static string apiArguments = "/json/";


map<pair<string, string>, pair<string, vector<int>>> globalDict;


class Client {
public:

    static string getResponse(const string &ip) {
        boost::asio::io_context io;
        boost::asio::ip::tcp::resolver resolver(io);
        boost::asio::ip::tcp::socket socket(io);
        boost::asio::connect(socket, resolver.resolve(mainApi, "80"));

        string arg = apiArguments + ip;
        http::request<http::string_body> req(http::verb::get, arg, 11);

        req.set(http::field::host, mainApi);
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

        http::write(socket, req);
        string response;
        {
            boost::beast::flat_buffer buffer;
            http::response<http::dynamic_body> res;
            http::read(socket, buffer, res);
            response = boost::beast::buffers_to_string(res.body().data());
        }
        socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both);
        return response;
    }
};

struct sniff_ip {
    u_char ip_vhl;                 // версия << 4 | длина заголовка >> 2
    u_char ip_tos;                 // тип службы
    u_short ip_len;                 // общая длина
    u_short ip_id;                  // идентефикатор
    u_short ip_off;                 // поле фрагмента смещения
#define IP_RF 0x8000            // reserved флаг фрагмента
#define IP_DF 0x4000            // dont флаг фрагмента
#define IP_MF 0x2000            // more флаг фрагмента
#define IP_OFFMASK 0x1fff       // маска для битов фрагмента
    u_char ip_ttl;                 // время жизни
    u_char ip_p;                   // протокол
    u_short ip_sum;                 //контрольная сумма
    struct in_addr ip_src, ip_dst;   //адрес источника и адрес назначения
};

string parseJson(string jsonString, string field) {
    if (jsonString.length() != 0) {
        stringstream jsonEncoded(jsonString);
        boost::property_tree::ptree root;
        boost::property_tree::read_json(jsonEncoded, root);

        if (!root.empty()) {
            return root.get<string>(field);
        }
    }
    return "";
}


void refreshJson(string JSON, string ip, int count, bool T, const struct pcap_pkthdr *header) {
    string country, org;
    if (parseJson(JSON, "status") == "success") {
        country = parseJson(JSON, "country");
        org = parseJson(JSON, "isp");
        pair<string, string> key = {country, org};
        if (globalDict.find(key) == globalDict.end()) {
            globalDict[key].first = ip;
            globalDict[key].second = {count, 0, static_cast<int>(header->len)};
        } else {
            globalDict[key].second[T] += count;
            globalDict[key].second[2] += static_cast<int>(header->len);
        }

    }
}


void packetAnalyze(u_char *arg, const struct pcap_pkthdr *header, const u_char *packet) {
    end_time = clock();

    static int count = 0;
    count++;

    const struct sniff_ip *ip;              // The IP header

    int size_ip;

    // смещение заголовка IP
    ip = (struct sniff_ip *) (packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        BOOST_LOG_TRIVIAL(warning) << "   * Invalid IP header length: " << size_ip << " bytes";
        return;
    }
    string from_ip = inet_ntoa(ip->ip_src);
    string to_ip = inet_ntoa(ip->ip_dst);
    string jSON_from = Client::getResponse(from_ip);
    string jSON_to = Client::getResponse(to_ip);
    string country;
    string org;
    refreshJson(jSON_from, from_ip, count, false, header);
    refreshJson(jSON_to, to_ip, count, true, header);
    local_start_time += clock() - end_time;
    BOOST_LOG_TRIVIAL(info) << "Процент прохождения сеанса прослушивания: "
                            << 0.1 * (end_time - start_time) / (local_start_time + 100);
    //cout << jSON_from << endl;
}


void sniff_function() {
    int packet;
    bpf_program fp{};
//    скомпилированный фильтр

    bpf_u_int32 mask;  // Сетевая маска устройства
    bpf_u_int32 net;  // IP устройства
    const u_char *pkt_data;
    pcap_pkthdr *header;
    pcap_if_t *dev = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE] = {0}; // сюда записывается ошибка
    pcap_if_t *fptr;

// дескриптор устройства
    pcap_t *handle;

    //    поиск сетевого интерфейса
    if (pcap_findalldevs(&dev, errbuf) != 0) {
        cout << errbuf;
        return;
    }
    cout << "Сетевой интерфейс: " << dev->name << endl;

    pcap_lookupnet(dev->name, &net, &mask, reinterpret_cast<char *>(errbuf));
    //    теперь устройтсво надо открыть для прослушивания; ошибка же опять будет сохраняться в errbuf
    handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        BOOST_LOG_TRIVIAL(error) << errbuf;
        return;
    }
    if (pcap_datalink(handle) != DLT_EN10MB) {
        BOOST_LOG_TRIVIAL(error) << "Нет поддержки заголовков канального уровня";
        return;
    }

    packet = pcap_loop(handle, 100, packetAnalyze, NULL);
//        Закрытие сессии
    pcap_close(handle);

}


int main() {

    for (int i = 0; i < 10; i++) {
        cout << "Сеанс номер " << i + 1 << endl;
        sniff_function();
        start_time = clock();
        for (const auto &x: globalDict) {
            cout << "Country: " << x.first.first << endl;
            cout << "isp: " << x.first.second << endl;

            cout << "IP: " << x.second.first << endl;
            cout << "Количество пакетов (IN): " << x.second.second[0] << endl;
            cout << "Количество пакетов (OUT): " << x.second.second[1] << endl;
            cout << "Суммарная длина пакетов (байт): " << x.second.second[2] << endl;
            cout << "*************************************************************************************" << endl;
        }
        sleep(2);
    }


    return 0;
}
