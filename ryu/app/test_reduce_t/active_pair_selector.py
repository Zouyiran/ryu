#!/usr/bin/env python
# -*- coding: utf-8 -*-

import numpy as np

import matplotlib.pyplot as plt
from matplotlib.colors import Normalize

from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn import svm, cross_validation, datasets
from sklearn.cross_validation import StratifiedShuffleSplit
from sklearn.grid_search import GridSearchCV

from flow_classifier import FlowClassifier

class ActivePairSelector(object):
    def __init__(self):
        super(ActivePairSelector, self).__init__()

        self.flowClassifier = FlowClassifier()

    def pre_process(self):
        data = self.flowClassifier.get_data(self.flowClassifier.data)
        scaler = StandardScaler()
        data = scaler.fit_transform(data)
        target = self.flowClassifier.get_target(self.flowClassifier.target)

        C_range = np.logspace(-2, 10, 13)
        gamma_range = np.logspace(-9, 3, 13)
        param_grid = dict(gamma=gamma_range, C=C_range)
        cv = StratifiedShuffleSplit(target, n_iter=5, test_size=0.2, random_state=42)
        grid = GridSearchCV(SVC(), param_grid=param_grid, cv=cv)
        grid.fit(data, target)
        scores = [x[1] for x in grid.grid_scores_]
        scores = np.array(scores).reshape(len(C_range), len(gamma_range))

        print("The best parameters are %s with a score of %0.2f"
              % (grid.best_params_, grid.best_score_))

        plt.figure(figsize=(8, 6))
        plt.subplots_adjust(left=.2, right=0.95, bottom=0.15, top=0.95)
        plt.imshow(scores, interpolation='nearest', cmap=plt.cm.hot,
                   norm=MidpointNormalize(vmin=0.2, midpoint=0.92))
        plt.xlabel('gamma',fontsize=16)
        plt.ylabel('C',fontsize=16)
        plt.colorbar()
        plt.xticks(np.arange(len(gamma_range)), gamma_range, rotation=45,fontsize=16)
        plt.yticks(np.arange(len(C_range)), C_range,fontsize=16)
        plt.show()

class MidpointNormalize(Normalize):

    def __init__(self, vmin=None, vmax=None, midpoint=None, clip=False):
        self.midpoint = midpoint
        Normalize.__init__(self, vmin, vmax, clip)

    def __call__(self, value, clip=None):
        x, y = [self.vmin, self.midpoint, self.vmax], [0, 0.5, 1]
        return np.ma.masked_array(np.interp(value, x, y))

if __name__ == "__main__":
    APS = ActivePairSelector()
    APS.pre_process()

