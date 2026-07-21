"""Tests for the image (PNG LSB) steganography method.

Run with: python -m pytest tests/test_steg_img.py
Requires Pillow (soft dep in steg.py). CI installs it via requirements.txt.
"""
import io
import os
import random

import pytest

from steg import img_capacity, hide, reveal


# ---------------------------------------------------------------------------
# capacity helper (no Pillow needed)
# ---------------------------------------------------------------------------

def test_img_capacity_rgb():
    # width*height*3 channels // 8 bits/byte, minus 4-byte length header
    assert img_capacity(256, 256) == (256 * 256 * 3) // 8 - 4


def test_img_capacity_rectangular():
    assert img_capacity(100, 50) == (100 * 50 * 3) // 8 - 4


def test_img_capacity_negative_dim_raises():
    with pytest.raises(ValueError):
        img_capacity(-1, 10)
    with pytest.raises(ValueError):
        img_capacity(10, -1)


def test_img_capacity_zero_dim_raises():
    # zero-size image can't hold anything; signal as ValueError so the
    # caller path (cover too small) gets a single error class to catch
    with pytest.raises(ValueError):
        img_capacity(0, 10)
    with pytest.raises(ValueError):
        img_capacity(10, 0)


def test_img_capacity_non_int_raises():
    with pytest.raises(TypeError):
        img_capacity(1.5, 10)
    with pytest.raises(TypeError):
        img_capacity(10, "10")
