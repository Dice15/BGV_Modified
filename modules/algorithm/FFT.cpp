#include "FFT.h"
#include <cmath>

FFT::FFT() {}
FFT::~FFT() {}

unsigned int FFT::reverse_bits(unsigned int x, int log2n) const {
    unsigned int n = 0;
    for (int i = 0; i < log2n; ++i) {
        n <<= 1;
        n |= (x & 1);
        x >>= 1;
    }
    return n;
}

void FFT::fft_transform(std::vector<std::complex<double_t>>& a) const {
    int n = a.size();
    int log2n = 0;
    while ((1 << log2n) < n) log2n++;

    // ��Ʈ ���� ������ �迭 ��迭
    for (unsigned int i = 0; i < n; ++i) {
        unsigned int j = reverse_bits(i, log2n);
        if (j > i) std::swap(a[i], a[j]);
    }

    // Danielson-Lanczos �ܰ�
    for (int s = 1; s <= log2n; ++s) {
        int m = 1 << s; // ���� �ܰ��� ������ ũ��
        double_t angle = -2.0 * PI / m;
        std::complex<double_t> wm(std::cos(angle), std::sin(angle));
        for (int k = 0; k < n; k += m) {
            std::complex<double_t> w(1, 0);
            for (int j = 0; j < m / 2; ++j) {
                std::complex<double_t> t = w * a[k + j + m / 2];
                std::complex<double_t> u = a[k + j];
                a[k + j] = u + t;
                a[k + j + m / 2] = u - t;
                w *= wm;
            }
        }
    }
}

std::vector<std::complex<double_t>> FFT::compute_fft(const std::vector<double_t>& input) {
    // �Է� ũ�� Ȯ�� �� 2�� �ŵ��������� �е�
    size_t n = 1;
    while (n < input.size()) n <<= 1;
    std::vector<std::complex<double_t>> a(n, 0.0);
    for (size_t i = 0; i < input.size(); ++i) {
        a[i] = std::complex<double_t>(input[i], 0.0);
    }

    // FFT ��ȯ ����
    fft_transform(a);

    return a;
}

// IFFT ���� �޼���
std::vector<std::complex<double_t>> FFT::compute_ifft(const std::vector<std::complex<double_t>>& input) {
    // �Է� ũ�� Ȯ�� �� 2�� �ŵ��������� �е�
    size_t n = 1;
    while (n < input.size()) n <<= 1;
    std::vector<std::complex<double_t>> a(n, 0.0);
    for (size_t i = 0; i < input.size(); ++i) {
        // IFFT�� ���� �������� ����� ��ȣ�� ������Ŵ
        a[i] = std::complex<double_t>(input[i].real(), -input[i].imag());
    }

    // FFT ��ȯ ����
    fft_transform(a);

    // ����� ����� ��ȣ�� �ٽ� ������Ű�� �����ϸ�
    for (auto& c : a) {
        c = std::complex<double_t>(c.real() / n, -c.imag() / n);
    }

    return a;
}