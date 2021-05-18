//
//  ContentView.swift
//  KCPG
//
//  Created by Stefan Walkner on 17.05.21.
//

import SwiftUI

struct ContentView: View {
    let viewModel = ViewModel()
    var body: some View {
        Text("Hello, world!")
            .padding()
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
