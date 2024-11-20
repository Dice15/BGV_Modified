/*
 * Copyright (c) 2012-2013 Haitham Hassanieh, Piotr Indyk, Dina Katabi,
 *   Eric Price, Massachusetts Institute of Technology
 * Copyright (c) 2012-2013 Jörn Schumacher, ETH Zurich
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 *
 */

#include "fftw.h"
#include<map>

#include "flopcount.h"

std::map < int, fftw_plan > fftw_plans;

int fftw_dft(complex_t* out, int n, complex_t* x, int backwards) {
    fftw_plan p;

    if (OPTIMIZE_FFTW) {
        if (fftw_plans.find(n) == fftw_plans.end()) {
            fftw_complex* in = 
                reinterpret_cast<fftw_complex*>(fftw_malloc(sizeof(fftw_complex) * n));
            fftw_complex* out2 = 
                reinterpret_cast<fftw_complex*>(fftw_malloc(sizeof(fftw_complex) * n));
            p = fftw_plan_dft_1d(n, in, out2,
                backwards ? FFTW_BACKWARD :
                FFTW_FORWARD, FFTW_MEASURE);
            fftw_plans.insert(std::make_pair(n, p));
            fftw_free(in);
            fftw_free(out2);
        }
    }


    fftw_complex* fftw_x =
        reinterpret_cast<fftw_complex*>(fftw_malloc(sizeof(fftw_complex) * n));
    fftw_complex* fftw_out =
        reinterpret_cast<fftw_complex*>(fftw_malloc(sizeof(fftw_complex) * n));

    for (int i = 0; i < n; ++i) {
        fftw_x[i][0] = x[i].real();
        fftw_out[i][1] = x[i].imag();
    }

    p = fftw_plan_dft_1d(n, fftw_x, fftw_out,
        backwards ? FFTW_BACKWARD : FFTW_FORWARD, 
        FFTW_ESTIMATE);

    FLOPCOUNT_INCREMENT_FFTW_PLAN(p);

    fftw_execute(p);

    for (int i = 0; i < n; ++i) {
        out[i] = complex_t(fftw_out[i][0], fftw_out[i][1]);
    }

    fftw_destroy_plan(p);
    fftw_free(fftw_x);
    fftw_free(fftw_out);

    return 0;
}