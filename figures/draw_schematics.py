"""Draw the manuscript schematics directly as font-embedded vector PDFs.

Run: python figures/draw_schematics.py --output figures
Requires Python 3.9+ and Matplotlib. No TeX engine or network is used.
The diagrams express the defined model; they are not measurement plots.
"""
import argparse
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle, Polygon, Circle, FancyArrowPatch
from matplotlib.path import Path as DrawingPath

plt.rcParams.update({'font.family':'STIXGeneral', 'mathtext.fontset':'stix',
                     'font.size':9, 'pdf.fonttype':42, 'ps.fonttype':42,
                     'text.usetex':False, 'axes.unicode_minus':False})
CM = 1 / 2.54

class Drawing:
    def __init__(self, bounds):
        x0,y0,x1,y1 = bounds
        self.fig = plt.figure(figsize=((x1-x0)*CM,(y1-y0)*CM))
        self.ax = self.fig.add_axes([0,0,1,1], xlim=(x0,x1), ylim=(y0,y1))
        self.ax.set_aspect('equal'); self.ax.axis('off')
        self.nodes = {}
        self.labels = []
        self.routes = []

    def text(self,x,y,label,size=9,ha='center',va='center'):
        artist=self.ax.text(x,y,label,fontsize=size,ha=ha,va=va,
                            linespacing=1.15,clip_on=False,zorder=4)
        self.labels.append([artist,None])
        return artist

    def box(self,name,x,y,w,h,label,dashed=False,shape='rect',size=9,gray=1):
        style = {'edgecolor':'black','facecolor':str(gray),'linewidth':.6,
                 'linestyle':(0,(4,3)) if dashed else 'solid', 'zorder':2}
        if shape == 'diamond':
            obj = Polygon([(x-w/2,y),(x,y+h/2),(x+w/2,y),(x,y-h/2)],**style)
        elif shape == 'circle': obj = Circle((x,y),w/2,**style)
        else: obj = Rectangle((x-w/2,y-h/2),w,h,**style)
        self.ax.add_patch(obj); self.text(x,y,label,size)
        self.labels[-1][1]=(x-w/2,y-h/2,x+w/2,y+h/2)
        self.nodes[name] = (x,y,w,h,shape)

    def point(self,name,side):
        x,y,w,h,_ = self.nodes[name]
        return {'n':(x,y+h/2),'s':(x,y-h/2),'e':(x+w/2,y),
                'w':(x-w/2,y),'nw':(x-w/2,y+h/2),
                'ne':(x+w/2,y+h/2),'c':(x,y)}[side]

    def line(self,points,dashed=False):
        self.routes.append(points)
        xs,ys=zip(*points)
        self.ax.plot(xs,ys,color='black',linewidth=.55,
                     linestyle=(0,(4,3)) if dashed else 'solid',zorder=1)

    def arrow(self,p,q,dashed=False,via=()):
        points=[p,*via,q]
        self.routes.append(points[-2:])
        if via:self.line(points[:-1],dashed)
        self.ax.add_patch(FancyArrowPatch(points[-2],points[-1],
                         arrowstyle='-|>',mutation_scale=7.5,linewidth=.55,
                         color='black',shrinkA=0,shrinkB=0,
                         linestyle=(0,(4,3)) if dashed else 'solid',zorder=1))

    def edge(self,a,b,sa='s',sb='n',**kwargs):
        self.arrow(self.point(a,sa),self.point(b,sb),**kwargs)

    def frame(self,x,y,w,h):
        self.ax.add_patch(Rectangle((x,y),w,h,fill=False,edgecolor='black',
                                   linewidth=.55,linestyle=(0,(4,3)),zorder=0))

    def save(self,out,name):
        # Fixed physical canvas: do not enlarge or rasterize the scientific figure.
        self.fig.canvas.draw()
        renderer=self.fig.canvas.get_renderer()
        x0,x1=self.ax.get_xlim();y0,y1=self.ax.get_ylim()
        measured=[]
        for artist,node in self.labels:
            b=artist.get_window_extent(renderer).transformed(self.ax.transData.inverted())
            measured.append((artist,b))
            if b.x0<x0-.02 or b.x1>x1+.02 or b.y0<y0-.02 or b.y1>y1+.02:
                raise ValueError(name+': clipped label '+repr(artist.get_text()))
            if node and (b.x0<node[0]-.02 or b.x1>node[2]+.02 or b.y0<node[1]-.02 or b.y1>node[3]+.02):
                raise ValueError(name+': label exceeds node '+repr(artist.get_text()))
        for i,(artist,b) in enumerate(measured):
            for other,area in measured[i+1:]:
                if b.overlaps(area):raise ValueError(name+': overlapping labels')
        modules=[]
        for x,y,w,h,_ in self.nodes.values():
            from matplotlib.transforms import Bbox
            modules.append(Bbox.from_extents(x-w/2+.02,y-h/2+.02,x+w/2-.02,y+h/2-.02))
        for i,area in enumerate(modules):
            if any(area.overlaps(other) for other in modules[i+1:]):
                raise ValueError(name+': overlapping modules')
        for route in self.routes:
            path=DrawingPath(route)
            if any(path.intersects_bbox(b,filled=False) for b in modules):
                raise ValueError(name+': route crosses module interior')
            if any(path.intersects_bbox(b.padded(.025),filled=False) for _,b in measured):
                raise ValueError(name+': route crosses label')
        self.fig.savefig(out/(name+'.pdf'),format='pdf',
                         metadata={'Creator':'Python Matplotlib','Producer':None,
                                   'CreationDate':None,'ModDate':None})
        plt.close(self.fig)

def draw(out):
    d=Drawing((-1.7,-2.75,6.6,.7))
    d.box('root',0,0,3.2,1,'Root $r$ in $n_0$\nauthenticated head',size=8.5)
    d.box('dep',4.8,0,3.2,1,'Dependency $d$ in $n_1$\nauthenticated head',size=8.5)
    d.edge('root','dep','e','w');d.text(2.4,.3,'depends on',size=8.5)
    d.box('other',2.4,-1.65,4.6,.9,'Unrelated namespace $n_5$',size=8.5,dashed=True)
    d.text(2.4,-2.4,'may be disconnected',size=8.5)
    d.save(out,'dependency-footprint')

    d=Drawing((-4.1,-4.6,4.1,.7))
    d.box('seq',0,0,5.5,1,'Namespace sequencer\nauthenticated history + scope body',size=8.5)
    for i,x in enumerate([-3,-1,1,3]):
        d.box('w'+str(i),x,-1.9,1.7,1.55,'$w_'+str(i)+'$\nreplay\npersist\nsign',size=8.5)
    d.box('client',0,-3.85,7.5,1.1,'Client: authority + any 3 distinct witnesses\nverify scope, frontier and freshness',size=8.5,gray=.95)
    d.line([(0,-.5),(0,-.84)])
    d.line([(-3,-.84),(3,-.84)])
    for i,x in enumerate([-3,-1,1,3]):
        d.arrow((x,-.84),d.point('w'+str(i),'n'))
        d.arrow(d.point('w'+str(i),'s'),(x,-3.30))
    d.save(out,'witnessed-scope')

if __name__ == "__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",type=Path,default=Path(__file__).resolve().parent)
    output=parser.parse_args().output
    output.mkdir(parents=True,exist_ok=True)
    draw(output)
