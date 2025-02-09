#pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <stdexcept>

/**
 * A class that duplicates the output stream to both the console and a file.
 *
 * TeeStream enables simultaneous output to the console (via `std::cout`) and a file.
 * It redirects `std::cout` to write data both to its original destination (the console)
 * and to a specified file.
 */
class TeeStream : public std::ostream
{
public:
    /**
     * Constructor that initializes the TeeStream.
     *
     * Opens the specified file for writing and redirects `std::cout`
     * to write to both the console and the file.
     * Existing file content is removed upon opening.
     *
     * @param filename The name of the file where output will also be written.
     * @throws std::ios_base::failure If the file cannot be opened.
     */
    TeeStream(const std::string& filename) : std::ostream(std::cout.rdbuf()), file_(filename, std::ios::out | std::ios::trunc)
    {
        if (!file_.is_open())
        {
            throw std::ios_base::failure("Failed to open file");
        }
        console_buf_ = std::cout.rdbuf();
        std::cout.rdbuf(this->rdbuf());
    }

    /**
     * Destructor that restores the original `std::cout` buffer.
     *
     * Ensures that `std::cout` is restored to its original state when the
     * TeeStream object is destroyed.
     */
    ~TeeStream()
    {
        std::cout.rdbuf(console_buf_);
    }

    /**
     * Template-based overloaded output operator for general data types.
     *
     * Ensures that the given value is written to both the console and the file.
     *
     * @tparam T The type of the value to be written.
     * @param value The value to be written.
     * @return A reference to the current stream (`*this`).
     */
    template <typename T>
    TeeStream& operator<<(const T& value)
    {
        std::cout << value;
        file_ << value;
        return *this;
    }

    /**
     * Overloaded output operator for stream manipulators (e.g., `std::endl`).
     *
     * Ensures that manipulators like `std::endl` are applied to both the console and the file.
     *
     * @param manip The stream manipulator to be applied.
     * @return A reference to the current stream (`*this`).
     */
    TeeStream& operator<<(std::ostream& (*manip)(std::ostream&))
    {
        manip(std::cout);
        manip(file_);
        return *this;
    }

private:
    std::ofstream file_;

    std::streambuf* console_buf_;
};
