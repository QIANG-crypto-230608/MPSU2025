#include "BIGNUM_Trans_operation.h"


std::vector<uint8_t> serializeBlocks(const std::vector<std::vector<osuCrypto::block>>& sw)
{
    std::vector<uint8_t> serialized;

    for(const auto& vec : sw){
        uint32_t vec_size = static_cast<uint32_t>(vec.size());
        serialized.insert(serialized.end(), reinterpret_cast<uint8_t*>(&vec_size),
                          reinterpret_cast<uint8_t*>(&vec_size)+sizeof(vec_size));

        for(const auto& blk : vec){
            serialized.insert(serialized.end(), reinterpret_cast<const uint8_t*>(&blk),
                              reinterpret_cast<const uint8_t*>(&blk)+sizeof(osuCrypto::block));
        }
    }

    return serialized;
}




std::vector<std::vector<osuCrypto::block>> deserializeBlocks(const uint8_t* data, size_t& local_offset, size_t data_size)
{
    std::vector<std::vector<osuCrypto::block>> sw;

    while (local_offset < data_size) {
        if (local_offset + sizeof(uint32_t) > data_size) {
            throw std::runtime_error("Insufficient data for vec_size");
        }

        uint32_t vec_size;
        memcpy(&vec_size, data + local_offset, sizeof(uint32_t));
        local_offset += sizeof(uint32_t);

        std::vector<osuCrypto::block> vec;
        vec.reserve(vec_size);

        for (uint32_t i = 0; i < vec_size; ++i) {
            if (local_offset + sizeof(osuCrypto::block) > data_size) {
                throw std::runtime_error("Insufficient data for block");
            }

            osuCrypto::block blk;
            memcpy(&blk, data + local_offset, sizeof(osuCrypto::block));
            local_offset += sizeof(osuCrypto::block);
            vec.push_back(blk);
        }

        sw.push_back(std::move(vec));
    }

    return sw;
}


std::vector<uint8_t> serializeBIGNUM(BIGNUM* bn){
    if(!bn) return {};

    int bn_size = BN_num_bytes(bn);
    std::vector<uint8_t> serialized(sizeof(uint32_t) + bn_size);

    uint32_t size = static_cast<uint32_t>(bn_size);
    memcpy(serialized.data(), &size, sizeof(uint32_t));

    BN_bn2bin(bn, serialized.data() + sizeof(uint32_t));

    return serialized;
}


BIGNUM* deserializeBIGNUM(const uint8_t* data, size_t& offset)
{
    if(!data) return nullptr;

    uint32_t size;
    memcpy(&size, data + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    BIGNUM * bn = BN_bin2bn(data +offset, size, nullptr);
    offset += size;

    return bn;
}


std::vector<uint8_t> serializeVector(const std::vector<std::pair<BIGNUM*, BIGNUM*>>& A)
{
    std::vector<uint8_t> serialized;

    for (const auto& pair : A) {
        // Serialize first BIGNUM
        uint32_t first_len = static_cast<uint32_t>(BN_num_bytes(pair.first));
        serialized.insert(serialized.end(),
                          reinterpret_cast<uint8_t*>(&first_len),
                          reinterpret_cast<uint8_t*>(&first_len) + sizeof(first_len));
        std::vector<uint8_t> first_bytes(first_len);
        BN_bn2bin(pair.first, first_bytes.data());
        serialized.insert(serialized.end(), first_bytes.begin(), first_bytes.end());

        // Serialize second BIGNUM
        uint32_t second_len = static_cast<uint32_t>(BN_num_bytes(pair.second));
        serialized.insert(serialized.end(),
                          reinterpret_cast<uint8_t*>(&second_len),
                          reinterpret_cast<uint8_t*>(&second_len) + sizeof(second_len));
        std::vector<uint8_t> second_bytes(second_len);
        BN_bn2bin(pair.second, second_bytes.data());
        serialized.insert(serialized.end(), second_bytes.begin(), second_bytes.end());
    }

    return serialized;
}



std::vector<std::pair<BIGNUM*, BIGNUM*>> deserializeVector(const uint8_t* data, uint32_t size_A)
{
    std::vector<std::pair<BIGNUM*, BIGNUM*>> A;
    size_t offset = 0;

    while (offset < size_A) {
        // Deserialize first BIGNUM
        if (offset + sizeof(uint32_t) > size_A) {
            throw std::runtime_error("Insufficient data for first BIGNUM length");
        }
        uint32_t first_len;
        std::memcpy(&first_len, data + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        if (offset + first_len > size_A) {
            throw std::runtime_error("Insufficient data for first BIGNUM");
        }
        BIGNUM* first = BN_bin2bn(data + offset, first_len, NULL);
        if (!first) {
            throw std::runtime_error("Failed to deserialize first BIGNUM");
        }
        offset += first_len;

        // Deserialize second BIGNUM
        if (offset + sizeof(uint32_t) > size_A) {
            BN_free(first);
            throw std::runtime_error("Insufficient data for second BIGNUM length");
        }
        uint32_t second_len;
        std::memcpy(&second_len, data + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        if (offset + second_len > size_A) {
            BN_free(first);
            throw std::runtime_error("Insufficient data for second BIGNUM");
        }
        BIGNUM* second = BN_bin2bn(data + offset, second_len, NULL);
        if (!second) {
            BN_free(first);
            throw std::runtime_error("Failed to deserialize second BIGNUM");
        }
        offset += second_len;

        A.emplace_back(first, second);
    }

    return A;
}


std::vector<uint8_t> serializeData(const std::vector<std::pair<BIGNUM*, BIGNUM*>>& data)
{
    std::vector<uint8_t> serialized;

    // Serialize the data vector
    std::vector<uint8_t> serialized_data = serializeVector(data);
    uint32_t size_data = static_cast<uint32_t>(serialized_data.size());

    // Serialize the size of data in network byte order
    uint32_t size_network_order = htonl(size_data);
    serialized.insert(serialized.end(),
                      reinterpret_cast<uint8_t*>(&size_network_order),
                      reinterpret_cast<uint8_t*>(&size_network_order) + sizeof(size_network_order));

    // Serialize the data itself
    serialized.insert(serialized.end(), serialized_data.begin(), serialized_data.end());

    return serialized;
}


void deserializeData(const uint8_t* data, size_t data_size,
                     std::vector<std::pair<BIGNUM*, BIGNUM*>>& data_out)
{
    size_t offset = 0;

    // Deserialize the size of data
    if (offset + sizeof(uint32_t) > data_size) {
        throw std::runtime_error("Insufficient data for size_data");
    }
    uint32_t size_network_order;
    std::memcpy(&size_network_order, data + offset, sizeof(uint32_t));
    uint32_t size_data = ntohl(size_network_order);
    offset += sizeof(uint32_t);

    if (offset + size_data > data_size) {
        throw std::runtime_error("Insufficient data for serialized data");
    }

    // Deserialize the data vector
    data_out = deserializeVector(data + offset, size_data);
    offset += size_data;
}


void BIGNUM_server(const std::vector<std::pair<BIGNUM*, BIGNUM*>>& data)
{
    try{
        boost::asio::io_service io_service;

        boost::asio::ip::tcp::acceptor acceptor(io_service,
                                                boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 9999));

        boost::asio::ip::tcp::socket socket(io_service);
        acceptor.accept(socket);

        std::vector<uint8_t> serialized_data = serializeData(data);
        size_t data_length = serialized_data.size();
        const uint8_t* send_buffer = serialized_data.data();

        uint32_t length_to_send = static_cast<uint32_t>(data_length);
        uint32_t length_network_order = htonl(length_to_send);
        boost::asio::write(socket, boost::asio::buffer(&length_network_order, sizeof(length_network_order)));

        boost::asio::write(socket, boost::asio::buffer(send_buffer, data_length));

    } catch(std::exception& e){
        std::cerr << "[Server] Exception: " << e.what() << std::endl;
    }
}


void BIGNUM_client(std::vector<std::pair<BIGNUM*, BIGNUM*>>& data_out)
{
    try{
        boost::asio::io_service io_service;

        boost::asio::ip::tcp::socket socket(io_service);
        boost::asio::ip::tcp::resolver resolver(io_service);
        boost::asio::connect(socket, resolver.resolve({"127.0.0.1", "9999"}));

        uint32_t data_length_network_order;
        boost::asio::read(socket, boost::asio::buffer(&data_length_network_order, sizeof(data_length_network_order)));
        uint32_t data_length = ntohl(data_length_network_order);

        std::vector<uint8_t> recv_buffer(data_length);
        boost::asio::read(socket, boost::asio::buffer(recv_buffer.data(), data_length));

        oberg_comm += data_length;

        deserializeData(recv_buffer.data(), recv_buffer.size(), data_out);

    } catch(std::exception& e){
        std::cerr << "[Client] Exception: " << e.what() << std::endl;
    }
}



void sw_server(const std::vector<std::vector<osuCrypto::block>>& sw)
{
    try{
        boost::asio::io_service io_service;

        boost::asio::ip::tcp::acceptor acceptor(io_service,
                                                boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 9999));

        boost::asio::ip::tcp::socket socket(io_service);
        acceptor.accept(socket);

        std::vector<uint8_t> serialized_sw = serializeBlocks(sw);
        size_t data_length = serialized_sw.size();
        const uint8_t* send_buffer = serialized_sw.data();

        uint32_t length_to_send = static_cast<uint32_t>(data_length);
        uint32_t length_network_order = htonl(length_to_send);
        boost::asio::write(socket, boost::asio::buffer(&length_network_order, sizeof(length_network_order)));

        boost::asio::write(socket, boost::asio::buffer(send_buffer, data_length));

    } catch(std::exception& e){
        std::cerr << "[Server] Exception: " << e.what() << std::endl;
    }
}

void sw_client(std::vector<std::vector<osuCrypto::block>>& sw)
{
    try{
        boost::asio::io_service io_service;

        boost::asio::ip::tcp::socket socket(io_service);
        boost::asio::ip::tcp::resolver resolver(io_service);
        boost::asio::connect(socket, resolver.resolve({"127.0.0.1", "9999"}));

        uint32_t data_length_network_order;
        boost::asio::read(socket, boost::asio::buffer(&data_length_network_order, sizeof(data_length_network_order)));
        uint32_t data_length = ntohl(data_length_network_order);

        std::vector<uint8_t> recv_buffer(data_length);
        boost::asio::read(socket, boost::asio::buffer(recv_buffer.data(), data_length));

        oberg_comm += data_length;

        size_t offset = 0;
        sw = deserializeBlocks(recv_buffer.data(), offset, data_length);

    } catch(std::exception& e){
        std::cerr << "[Client] Exception: " << e.what() << std::endl;
    }
}


bool compareBIGNUMData(const std::vector<std::pair<BIGNUM*, BIGNUM*>>& sent_data,
                 const std::vector<std::pair<BIGNUM*, BIGNUM*>>& received_data)
{
    if(sent_data.size() != received_data.size()){
        return false;
    }

    for(size_t i = 0; i < sent_data.size(); ++i){
        const BIGNUM* sent_first = sent_data[i].first;
        const BIGNUM* sent_second = sent_data[i].second;
        const BIGNUM* received_first = received_data[i].first;
        const BIGNUM* received_second = received_data[i].second;

        if(BN_cmp(sent_first, received_first) != 0 ||
           BN_cmp(sent_second, received_second) != 0){
            return false;
        }
    }

    return true;
}

int betorg_count()
{
    return oberg_comm;
}

