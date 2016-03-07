#!/usr/bin/env python
# -*- coding: utf-8 -*-

import numpy as np
import matplotlib.pyplot as plt
from matplotlib.colors import Normalize

from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.datasets import load_iris
from sklearn.cross_validation import StratifiedShuffleSplit
from sklearn.grid_search import GridSearchCV

# from sklearn.model_selection import


class Classifier(object):
    def __init__(self):
        super(Classifier, self).__init__()

    def create_data(self, input_data):
        data = np.array(input_data)
        pass

    def create_target(self, input_target):
        target = np.array(input_target)
        pass

    def training(self):
        pass

    def verify(self):
        pass

    def get_module(self):
        pass