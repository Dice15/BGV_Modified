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


#include "timer.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <ctime>
#endif

#ifdef _WIN32
LARGE_INTEGER start_time, frequency;

void reset_timer() {
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start_time);
}

double get_time() {
    LARGE_INTEGER current_time;
    QueryPerformanceCounter(&current_time);
    return double(current_time.QuadPart - start_time.QuadPart) / frequency.QuadPart;
}
#else
#define TIMER_TYPE CLOCK_REALTIME

timespec start_time;

void reset_timer() {
    clock_gettime(TIMER_TYPE, &start_time);
}

double get_time() {
    timespec t;
    clock_gettime(TIMER_TYPE, &t);
    return double(t.tv_sec - start_time.tv_sec) + double(t.tv_nsec - start_time.tv_nsec) * 1.e-9;
}
#endif